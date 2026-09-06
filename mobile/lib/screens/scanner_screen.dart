/**
 * PhishShield TR - Scanner Screen
 * URL scanning and QR code scanning
 */

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:mobile_alert/mobile_alert.dart';
import '../models/models.dart';
import '../services/services.dart';

class ScannerScreen extends StatefulWidget {
  final ApiService apiService;
  final StorageService storageService;

  const ScannerScreen({
    super.key,
    required this.apiService,
    required this.storageService,
  });

  @override
  State<ScannerScreen> createState() => _ScannerScreenState();
}

class _ScannerScreenState extends State<ScannerScreen> {
  final TextEditingController _urlController = TextEditingController();
  bool _isLoading = false;
  AnalysisResult? _lastResult;

  @override
  void dispose() {
    _urlController.dispose();
    super.dispose();
  }

  Future<void> _analyzeUrl() async {
    final url = _urlController.text.trim();
    if (url.isEmpty) return;

    setState(() {
      _isLoading = true;
      _lastResult = null;
    });

    try {
      final result = await widget.apiService.analyzeUrl(url);
      
      // Save to history
      await widget.storageService.addToHistory(result);
      
      // Send event
      await widget.apiService.sendEvent({
        'url': url,
        'decision': result.decision,
        'risk_score': result.riskScore,
      });

      setState(() {
        _lastResult = result;
        _isLoading = false;
      });

      // Show notification for dangerous sites
      if (result.isDanger) {
        _showDangerNotification(result);
      }
    } catch (e) {
      setState(() {
        _isLoading = false;
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Hata: $e')),
        );
      }
    }
  }

  void _showDangerNotification(AnalysisResult result) {
    MobileAlert.show(
      title: 'Tehlikeli Site Tespit Edildi!',
      message: '${result.domain}\nRisk Skoru: ${result.riskScore}/100',
      type: AlertType.danger,
    );
  }

  void _pasteFromClipboard() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (data?.text != null) {
      _urlController.text = data!.text!;
    }
  }

  void _clearUrl() {
    _urlController.clear();
    setState(() {
      _lastResult = null;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('PhishShield TR'),
        backgroundColor: const Color(0xFF1a1a2e),
        foregroundColor: Colors.white,
        elevation: 0,
      ),
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [Color(0xFF1a1a2e), Color(0xFF16213e)],
          ),
        ),
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Logo/Header
              const Center(
                child: Text(
                  '🛡️',
                  style: TextStyle(fontSize: 64),
                ),
              ),
              const SizedBox(height: 8),
              const Center(
                child: Text(
                  'URL Scanner',
                  style: TextStyle(
                    fontSize: 24,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                  ),
                ),
              ),
              const SizedBox(height: 24),

              // URL Input
              Container(
                decoration: BoxDecoration(
                  color: Colors.white.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: TextField(
                  controller: _urlController,
                  style: const TextStyle(color: Colors.white),
                  decoration: InputDecoration(
                    hintText: 'URL girin veya yapistirin',
                    hintStyle: TextStyle(color: Colors.white.withOpacity(0.5)),
                    prefixIcon: const Icon(Icons.link, color: Colors.white54),
                    suffixIcon: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        IconButton(
                          icon: const Icon(Icons.paste, color: Colors.white54),
                          onPressed: _pasteFromClipboard,
                        ),
                        IconButton(
                          icon: const Icon(Icons.clear, color: Colors.white54),
                          onPressed: _clearUrl,
                        ),
                      ],
                    ),
                    border: InputBorder.none,
                    contentPadding: const EdgeInsets.symmetric(
                      horizontal: 16,
                      vertical: 14,
                    ),
                  ),
                  onSubmitted: (_) => _analyzeUrl(),
                ),
              ),
              const SizedBox(height: 16),

              // Scan Button
              ElevatedButton(
                onPressed: _isLoading ? null : _analyzeUrl,
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF00d4ff),
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(vertical: 16),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
                child: _isLoading
                    ? const SizedBox(
                        height: 20,
                        width: 20,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: Colors.white,
                        ),
                      )
                    : const Text(
                        'TARA',
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
              ),
              const SizedBox(height: 24),

              // Result
              if (_lastResult != null) _buildResultCard(),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildResultCard() {
    final result = _lastResult!;
    final isSafe = result.isSafe;
    final isDanger = result.isDanger;

    return Container(
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.1),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: isSafe
              ? Colors.green.withOpacity(0.5)
              : isDanger
                  ? Colors.red.withOpacity(0.5)
                  : Colors.orange.withOpacity(0.5),
          width: 2,
        ),
      ),
      padding: const EdgeInsets.all(20),
      child: Column(
        children: [
          // Status Icon
          Text(
            isSafe ? '🟢' : isDanger ? '🔴' : '🟠',
            style: const TextStyle(fontSize: 48),
          ),
          const SizedBox(height: 8),

          // Decision Badge
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            decoration: BoxDecoration(
              color: isSafe
                  ? Colors.green.withOpacity(0.2)
                  : isDanger
                      ? Colors.red.withOpacity(0.2)
                      : Colors.orange.withOpacity(0.2),
              borderRadius: BorderRadius.circular(20),
            ),
            child: Text(
              isSafe ? 'GÜVENLİ' : isDanger ? 'TEHLİKELİ' : 'İNCELENMELİ',
              style: TextStyle(
                color: isSafe
                    ? Colors.green
                    : isDanger
                        ? Colors.red
                        : Colors.orange,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
          const SizedBox(height: 16),

          // Domain
          Text(
            result.domain,
            style: const TextStyle(
              color: Colors.white,
              fontSize: 18,
              fontWeight: FontWeight.w500,
            ),
          ),
          const SizedBox(height: 12),

          // Score
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              _buildScoreChip(
                'Risk',
                '${result.riskScore}',
                isDanger ? Colors.red : Colors.orange,
              ),
              const SizedBox(width: 16),
              _buildScoreChip(
                'Güven',
                '${result.confidence}%',
                Colors.blue,
              ),
            ],
          ),
          const SizedBox(height: 16),

          // Reasons
          if (result.reasons.isNotEmpty) ...[
            const Text(
              'Nedenleri:',
              style: TextStyle(
                color: Colors.white70,
                fontSize: 12,
              ),
            ),
            const SizedBox(height: 8),
            ...result.reasons.take(5).map(
                  (r) => Padding(
                    padding: const EdgeInsets.symmetric(vertical: 2),
                    child: Row(
                      children: [
                        const Text('✓ ', style: TextStyle(color: Colors.green)),
                        Expanded(
                          child: Text(
                            r,
                            style: const TextStyle(color: Colors.white70),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
          ],

          // Cached indicator
          if (result.cached)
            const Padding(
              padding: EdgeInsets.only(top: 8),
              child: Text(
                '📱 Önbellekten',
                style: TextStyle(color: Colors.white38, fontSize: 12),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildScoreChip(String label, String value, Color color) {
    return Column(
      children: [
        Text(
          label,
          style: const TextStyle(color: Colors.white54, fontSize: 12),
        ),
        const SizedBox(height: 4),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          decoration: BoxDecoration(
            color: color.withOpacity(0.2),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Text(
            value,
            style: TextStyle(
              color: color,
              fontSize: 18,
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
      ],
    );
  }
}
