import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:twitter_sign_in/src/utils.dart';

// ignore: avoid_classes_with_only_static_members
class Oauth2 {
  static const String _oauth2TokenUrl =
      'https://api.twitter.com/2/oauth2/token';

  /// get applicatoin Bearer Token.
  ///
  /// https://developer.twitter.com/en/docs/authentication/oauth-2-0/application-only
  static Future<String?> getBearerToken({
    required String apiKey,
    required String apiSecretKey,
  }) async {
    final _httpClient = http.Client();
    final res = await _httpClient.post(
      Uri.parse('https://api.twitter.com/oauth2/token').replace(
        queryParameters: {'grant_type': 'client_credentials'},
      ),
      headers: <String, String>{
        'Authorization':
            'Basic ${base64Encode(utf8.encode('$apiKey:$apiSecretKey'))}'
      },
    );

    final json = jsonDecode(res.body) as Map<String, dynamic>;
    return json.get('access_token');
  }

  static Future<Map<String, dynamic>> exchangeAuthorizationCode({
    required String clientId,
    String? clientSecret,
    required String code,
    required String redirectUri,
    required String codeVerifier,
  }) async {
    final _httpClient = http.Client();

    final headers = <String, String>{
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    if (clientSecret != null && clientSecret.isNotEmpty) {
      headers['Authorization'] =
          'Basic ${base64Encode(utf8.encode('$clientId:$clientSecret'))}';
    }

    final res = await _httpClient.post(
      Uri.parse(_oauth2TokenUrl),
      headers: headers,
      body: <String, String>{
        'grant_type': 'authorization_code',
        'client_id': clientId,
        'code': code,
        'redirect_uri': redirectUri,
        'code_verifier': codeVerifier,
      },
    );

    final json = jsonDecode(res.body) as Map<String, dynamic>;
    if (res.statusCode < 200 || res.statusCode >= 300) {
      throw Exception('OAuth2 token exchange failed: ${jsonEncode(json)}');
    }
    return json;
  }

  static Future<Map<String, dynamic>> refreshToken({
    required String clientId,
    String? clientSecret,
    required String refreshToken,
  }) async {
    final _httpClient = http.Client();

    final headers = <String, String>{
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    if (clientSecret != null && clientSecret.isNotEmpty) {
      headers['Authorization'] =
          'Basic ${base64Encode(utf8.encode('$clientId:$clientSecret'))}';
    }

    final res = await _httpClient.post(
      Uri.parse(_oauth2TokenUrl),
      headers: headers,
      body: <String, String>{
        'grant_type': 'refresh_token',
        'client_id': clientId,
        'refresh_token': refreshToken,
      },
    );

    final json = jsonDecode(res.body) as Map<String, dynamic>;
    if (res.statusCode < 200 || res.statusCode >= 300) {
      throw Exception('OAuth2 refresh failed: ${jsonEncode(json)}');
    }
    return json;
  }
}
