/**
 * PhishShield TR - Alerts Screen
 * Security alerts and notifications
 */

import 'package:flutter/material.dart';
import '../models/models.dart';
import '../services/services.dart';

class AlertsScreen extends StatefulWidget {
  final StorageService storageService;

  const AlertsScreen({
    super.key,
    required this.storageService,
  });

  @override
  State<AlertsScreen> createState() => _AlertsScreenState();
}

class _AlertsScreenState extends State<AlertsScreen> {
  List<AlertItem> _alerts = [];
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadAlerts();
  }

  Future<void> _loadAlerts() async {
    setState(() => _isLoading = true);
    try {
      final alerts = await widget.storageService.getAlerts();
      setState(() {
        _alerts = alerts;
        _isLoading = false;
      });
    } catch (e) {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _resolveAlert(AlertItem alert) async {
    await widget.storageService.resolveAlert(alert.id);
    _loadAlerts();
  }

  Future<void> _clearAll() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Uyarları Temizle'),
        content: const Text('Tum uyarilar silinecek. Emin misiniz?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Iptal'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Sil'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      await widget.storageService.clearAlerts();
      _loadAlerts();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Uyarlar'),
        backgroundColor: const Color(0xFF1a1a2e),
        foregroundColor: Colors.white,
        actions: [
          if (_alerts.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.delete_outline),
              onPressed: _clearAll,
            ),
        ],
      ),
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [Color(0xFF1a1a2e), Color(0xFF16213e)],
          ),
        ),
        child: _isLoading
            ? const Center(child: CircularProgressIndicator())
            : _alerts.isEmpty
                ? _buildEmptyState()
                : _buildAlertsList(),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Text(
            '🔔',
            style: TextStyle(fontSize: 64),
          ),
          const SizedBox(height: 16),
          const Text(
            'Henuz uyari yok',
            style: TextStyle(
              color: Colors.white70,
              fontSize: 18,
            ),
          ),
          const SizedBox(height: 8),
          const Text(
            'Guvenli bir sistemsiniz',
            style: TextStyle(color: Colors.white38),
          ),
        ],
      ),
    );
  }

  Widget _buildAlertsList() {
    return RefreshIndicator(
      onRefresh: _loadAlerts,
      child: ListView.builder(
        itemCount: _alerts.length,
        padding: const EdgeInsets.all(8),
        itemBuilder: (context, index) {
          final alert = _alerts[index];
          return _buildAlertItem(alert);
        },
      ),
    );
  }

  Widget _buildAlertItem(AlertItem alert) {
    final isCritical = alert.severity == 'CRITICAL';
    final isWarning = alert.severity == 'WARNING';
    final isEmergency = alert.severity == 'EMERGENCY';

    Color severityColor;
    String icon;

    if (isEmergency) {
      severityColor = Colors.purple;
      icon = '🚨';
    } else if (isCritical) {
      severityColor = Colors.red;
      icon = '🔴';
    } else if (isWarning) {
      severityColor = Colors.orange;
      icon = '⚠️';
    } else {
      severityColor = Colors.blue;
      icon = 'ℹ️';
    }

    return Card(
      color: Colors.white.withOpacity(0.1),
      margin: const EdgeInsets.symmetric(vertical: 4),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Icon
            Container(
              width: 48,
              height: 48,
              decoration: BoxDecoration(
                color: severityColor.withOpacity(0.2),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Center(
                child: Text(icon, style: const TextStyle(fontSize: 24)),
              ),
            ),
            const SizedBox(width: 16),

            // Content
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          alert.title,
                          style: const TextStyle(
                            color: Colors.white,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ),
                      if (alert.resolved)
                        Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 8,
                            vertical: 2,
                          ),
                          decoration: BoxDecoration(
                            color: Colors.green.withOpacity(0.2),
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: const Text(
                            'Cozuldu',
                            style: TextStyle(
                              color: Colors.green,
                              fontSize: 10,
                            ),
                          ),
                        ),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Text(
                    alert.message,
                    style: const TextStyle(
                      color: Colors.white70,
                      fontSize: 13,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    _formatTime(alert.timestamp),
                    style: const TextStyle(
                      color: Colors.white38,
                      fontSize: 11,
                    ),
                  ),
                ],
              ),
            ),

            // Action
            if (!alert.resolved)
              IconButton(
                icon: const Icon(
                  Icons.check_circle_outline,
                  color: Colors.white38,
                ),
                onPressed: () => _resolveAlert(alert),
              ),
          ],
        ),
      ),
    );
  }

  String _formatTime(DateTime time) {
    final now = DateTime.now();
    final diff = now.difference(time);

    if (diff.inMinutes < 1) return 'Simdi';
    if (diff.inMinutes < 60) return '${diff.inMinutes} dk once';
    if (diff.inHours < 24) return '${diff.inHours} saat once';
    if (diff.inDays < 7) return '${diff.inDays} gun once';
    return '${time.day}/${time.month}/${time.year}';
  }
}
