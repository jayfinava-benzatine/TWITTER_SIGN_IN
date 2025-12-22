import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:twitter_sign_in/entity/auth_result.dart';
import 'package:twitter_sign_in/entity/user.dart';
import 'package:twitter_sign_in/schemes/access_token.dart';
import 'package:twitter_sign_in/schemes/request_token.dart';
import 'package:twitter_sign_in/src/auth_browser.dart';
import 'package:twitter_sign_in/src/exception.dart';
import 'package:twitter_sign_in/src/oauth_2.dart';
import 'package:twitter_sign_in/src/utils.dart';

/// The status after a Twitter login flow has completed.
enum TwitterLoginStatus {
  /// The login was successful and the user is now logged in.
  loggedIn,

  /// The user cancelled the login flow.
  cancelledByUser,

  /// The Twitter login completed with an error
  error,
}

///
class TwitterLogin {
  /// constructor
  TwitterLogin({
    required this.apiKey,
    required this.apiSecretKey,
    required this.redirectURI,
  });

  /// Consumer API key
  final String apiKey;

  /// Consumer API secret key
  final String apiSecretKey;

  /// Callback URL
  final String redirectURI;

  static const _channel = MethodChannel('twitter_login');
  static const _eventChannel = EventChannel('twitter_login/event');
  static final Stream<dynamic> _eventStream =
      _eventChannel.receiveBroadcastStream();

  static String getAuthorizationCodeFromRedirectUriV2(
    String redirectUrl, {
    String? expectedState,
  }) {
    final parsed = Uri.parse(redirectUrl);
    final queries = parsed.queryParameters;

    if (queries['denied'] != null) {
      throw const CanceledByUserException();
    }

    final error = queries['error'];
    if (error != null && error.isNotEmpty) {
      throw Exception('Error Response: $error');
    }

    final returnedState = queries['state'];
    if (expectedState != null && expectedState.isNotEmpty) {
      if (returnedState == null || returnedState != expectedState) {
        throw Exception('Invalid state returned from authorization.');
      }
    }

    final code = queries['code'];
    if (code == null || code.isEmpty) {
      throw Exception('Authorization code not found.');
    }

    return code;
  }

  /// Logs the user
  /// Forces the user to enter their credentials to ensure the correct users account is authorized.
  Future<AuthResult> login({bool forceLogin = false}) async {
    String? resultURI;
    RequestToken requestToken;
    try {
      requestToken = await RequestToken.getRequestToken(
        apiKey,
        apiSecretKey,
        redirectURI,
        forceLogin,
      );
    } on Exception {
      throw PlatformException(
        code: '400',
        message: 'Failed to generate request token.',
        details: 'Please check your APIKey or APISecret.',
      );
    }

    final uri = Uri.parse(redirectURI);
    final completer = Completer<String?>();
    StreamSubscription<void>? subscribe;

    if (Platform.isAndroid) {
      await _channel.invokeMethod('setScheme', uri.scheme);
      subscribe = _eventStream.listen((data) async {
        if (data['type'] == 'url') {
          if (!completer.isCompleted) {
            completer.complete(data['url']?.toString());
          } else {
            throw const CanceledByUserException();
          }
        }
      });
    }

    final authBrowser = AuthBrowser(
      onClose: () {
        if (!completer.isCompleted) {
          completer.complete(null);
        }
      },
    );

    try {
      if (Platform.isIOS || Platform.isMacOS) {
        /// Login to Twitter account with SFAuthenticationSession or ASWebAuthenticationSession.
        resultURI =
            await authBrowser.doAuth(requestToken.authorizeURI, uri.scheme);
      } else if (Platform.isAndroid) {
        // Login to Twitter account with chrome_custom_tabs.
        final success =
            await authBrowser.open(requestToken.authorizeURI, uri.scheme);
        if (!success) {
          throw PlatformException(
            code: '200',
            message:
                'Could not open browser, probably caused by unavailable custom tabs.',
          );
        }
        resultURI = await completer.future;
        await subscribe?.cancel();
      } else {
        throw PlatformException(
          code: '100',
          message: 'Not supported by this os.',
        );
      }

      // The user closed the browser.
      if (resultURI?.isEmpty ?? true) {
        throw const CanceledByUserException();
      }

      final queries = Uri.splitQueryString(Uri.parse(resultURI!).query);
      if (queries['error'] != null) {
        throw Exception('Error Response: ${queries['error']}');
      }

      // The user cancelled the login flow.
      if (queries['denied'] != null) {
        throw const CanceledByUserException();
      }

      final token = await AccessToken.getAccessToken(
        apiKey,
        apiSecretKey,
        queries,
      );

      if ((token.authToken?.isEmpty ?? true) ||
          (token.authTokenSecret?.isEmpty ?? true)) {
        return AuthResult(
          authToken: token.authToken,
          authTokenSecret: token.authTokenSecret,
          status: TwitterLoginStatus.error,
          errorMessage: 'Failed',
        );
      }

      User? user;

      try {
        user = await User.getUserData(
          apiKey,
          apiSecretKey,
          token.authToken!,
          token.authTokenSecret!,
        );
      } on Exception {
        debugPrint(
            'The rate limit may have been reached or the API may be restricted.');
      }

      return AuthResult(
        authToken: token.authToken,
        authTokenSecret: token.authTokenSecret,
        status: TwitterLoginStatus.loggedIn,
        user: user,
      );
    } on CanceledByUserException {
      return AuthResult(
        status: TwitterLoginStatus.cancelledByUser,
        errorMessage: 'The user cancelled the login flow.',
      );
    } catch (error) {
      return AuthResult(
        status: TwitterLoginStatus.error,
        errorMessage: error.toString(),
      );
    }
  }

  Future<String> getAuthorizationCode({
    String? codeVerifier,
    String? codeChallenge,
  }) async {
    String? resultURI;
    final uri = Uri.parse(redirectURI);

    if (codeChallenge != null && codeVerifier == null) {
      throw ArgumentError(
          'If you provide a codeChallenge, you must also provide the codeVerifier.');
    }

    final verifier = codeVerifier ?? createCryptoRandomString(64);
    final challenge = codeChallenge ?? createPkceCodeChallengeS256(verifier);
    final state = createCryptoRandomString(32);

    final authorizeUri =
        Uri.parse('https://twitter.com/i/oauth2/authorize').replace(
      queryParameters: <String, String>{
        'response_type': 'code',
        'client_id': apiKey,
        'redirect_uri': redirectURI,
        'scope': 'tweet.read users.read offline.access',
        'state': state,
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
      },
    );

    final completer = Completer<String?>();
    late StreamSubscription<void> subscribe;

    if (Platform.isAndroid) {
      await _channel.invokeMethod('setScheme', uri.scheme);
      subscribe = _eventStream.listen((data) async {
        if (data['type'] == 'url') {
          if (!completer.isCompleted) {
            completer.complete(data['url']?.toString());
          } else {
            throw const CanceledByUserException();
          }
        }
      });
    }

    final authBrowser = AuthBrowser(
      onClose: () {
        if (!completer.isCompleted) {
          completer.complete(null);
        }
      },
    );

    try {
      if (Platform.isIOS || Platform.isMacOS) {
        resultURI =
            await authBrowser.doAuth(authorizeUri.toString(), uri.scheme);
      } else if (Platform.isAndroid) {
        final success =
            await authBrowser.open(authorizeUri.toString(), uri.scheme);
        if (!success) {
          throw PlatformException(
            code: '200',
            message:
                'Could not open browser, probably caused by unavailable custom tabs.',
          );
        }
        resultURI = await completer.future;
      } else {
        throw PlatformException(
          code: '100',
          message: 'Not supported by this os.',
        );
      }

      if (resultURI?.isEmpty ?? true) {
        throw const CanceledByUserException();
      }

      return getAuthorizationCodeFromRedirectUriV2(
        resultURI!,
        expectedState: state,
      );
    } on CanceledByUserException {
      rethrow;
    } catch (error) {
      throw Exception('Failed to get authorization code: $error');
    } finally {
      await subscribe.cancel();
    }
  }

  Future<AuthResult> loginV2({
    bool forceLogin = false,
    String? codeVerifier,
    String? codeChallenge,
  }) async {
    // OAuth 2.0 Authorization Code with PKCE (User Access Token)
    // https://docs.x.com/fundamentals/authentication/oauth-2-0/user-access-token

    try {
      final code = await getAuthorizationCode(
        codeVerifier: codeVerifier,
        codeChallenge: codeChallenge,
      );

      final verifier = codeVerifier ?? createCryptoRandomString(64);

      final tokenJson = await Oauth2.exchangeAuthorizationCode(
        clientId: apiKey,
        clientSecret: apiSecretKey.isEmpty ? null : apiSecretKey,
        code: code,
        redirectUri: redirectURI,
        codeVerifier: verifier,
      );

      final accessToken = tokenJson.get<String>('access_token');
      if (accessToken == null || accessToken.isEmpty) {
        return AuthResult(
          authToken: null,
          authTokenSecret: null,
          status: TwitterLoginStatus.error,
          errorMessage: 'Failed to obtain access token.',
        );
      }

      User? user;
      try {
        user = await User.getUserDataV2(accessToken);
      } on Exception {
        debugPrint(
            'The rate limit may have been reached or the API may be restricted.');
      }

      return AuthResult(
        authToken: accessToken,
        authTokenSecret: null,
        status: TwitterLoginStatus.loggedIn,
        user: user,
      );
    } on CanceledByUserException {
      return AuthResult(
        status: TwitterLoginStatus.cancelledByUser,
        errorMessage: 'The user cancelled the login flow.',
      );
    } catch (error) {
      return AuthResult(
        status: TwitterLoginStatus.error,
        errorMessage: error.toString(),
      );
    }
  }
}
