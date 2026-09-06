/**
 * PhishShield TR - API Service
 * Mobile -> Backend iletisimi
 */

import 'dart:convert';
import 'package:http/http.dart' as http;
import '../models/models.dart';

class ApiService {
  final String baseUrl;
  final Map<String, AnalysisResult> _cache = {};
  final Duration cacheTTL;

  ApiService({
    this.baseUrl = 'http://127.0.0.1:8004',
    this.cacheTTL = const Duration(minutes: 5),
  });

  /**
   * URL'yi analiz et
   */
  Future<AnalysisResult> analyzeUrl(String url) async {
    // Cache kontrol
    final cached = _getCached(url);
    if (cached != null) {
      return cached;
    }

    try {
      final response = await http.post(
        Uri.parse('$baseUrl/api/v1/analyze'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'url': url}),
      );

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        final result = AnalysisResult.fromJson(data);
        _setCached(url, result);
        return result;
      } else {
        throw ApiException('HTTP ${response.statusCode}');
      }
    } catch (e) {
      throw ApiException('Analiz hatasi: $e');
    }
  }

  /**
   * Hızlı URL kontrolu
   */
  Future<AnalysisResult> checkUrl(String url) async {
    final cached = _getCached(url);
    if (cached != null) {
      return cached;
    }

    try {
      final response = await http.post(
        Uri.parse('$baseUrl/api/v1/check'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'url': url}),
      );

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        final result = AnalysisResult.fromJson(data);
        _setCached(url, result);
        return result;
      } else {
        throw ApiException('HTTP ${response.statusCode}');
      }
    } catch (e) {
      throw ApiException('Kontrol hatasi: $e');
    }
  }

  /**
   * Form analizi
   */
  Future<Map<String, dynamic>> analyzeForm(Map<String, dynamic> formData) async {
    try {
      final response = await http.post(
        Uri.parse('$baseUrl/api/v1/analyze-form'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(formData),
      );

      if (response.statusCode == 200) {
        return jsonDecode(response.body);
      } else {
        throw ApiException('HTTP ${response.statusCode}');
      }
    } catch (e) {
      throw ApiException('Form analiz hatasi: $e');
    }
  }

  /**
   * Feedback gonder
   */
  Future<bool> sendFeedback({
    required String url,
    required String feedbackType,
    String? note,
  }) async {
    try {
      final response = await http.post(
        Uri.parse('$baseUrl/api/v1/feedback'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'url': url,
          'feedback_type': feedbackType,
          'note': note,
        }),
      );

      return response.statusCode == 200;
    } catch (e) {
      return false;
    }
  }

  /**
   * Dashboard event gonder
   */
  Future<bool> sendEvent(Map<String, dynamic> eventData) async {
    try {
      final response = await http.post(
        Uri.parse('$baseUrl/api/v1/events'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'type': 'mobile_scan',
          'timestamp': DateTime.now().millisecondsSinceEpoch,
          ...eventData,
        }),
      );

      return response.statusCode == 200;
    } catch (e) {
      return false;
    }
  }

  /**
   * Cache islemleri
   */
  AnalysisResult? _getCached(String url) {
    final entry = _cache[url];
    if (entry == null) return null;

    if (DateTime.now().difference(entry.timestamp) > cacheTTL) {
      _cache.remove(url);
      return null;
    }

    return entry;
  }

  void _setCached(String url, AnalysisResult result) {
    _cache[url] = result;
  }

  void clearCache() {
    _cache.clear();
  }

  void removeFromCache(String url) {
    _cache.remove(url);
  }
}

class ApiException implements Exception {
  final String message;
  ApiException(this.message);

  @override
  String toString() => message;
}
