/**
 * PhishShield TR - History Screen
 * Scan history list
 */

import 'package:flutter/material.dart';
import '../models/models.dart';
import '../services/services.dart';

class HistoryScreen extends StatefulWidget {
  final StorageService storageService;
  final ApiService apiService;

  const HistoryScreen({
    super.key,
    required this.storageService,
    required this.apiService,
  });

  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  List<AnalysisResult> _history = [];
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadHistory();
  }

  Future<void> _loadHistory() async {
    setState(() => _isLoading = true);
    try {
      final history = await widget.storageService.getHistory();
      setState(() {
        _history = history;
        _isLoading = false;
      });
    } catch (e) {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _clearHistory() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Gecmisi Temizle'),
        content: const Text('Tum gecmis silinecek. Emin misiniz?'),
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
      await widget.storageService.clearHistory();
      _loadHistory();
    }
  }

  Future<void> _rescan(AnalysisResult item) async {
    try {
      final result = await widget.apiService.analyzeUrl(item.url);
      await widget.storageService.removeFromHistory(item.url);
      await widget.storageService.addToHistory(result);
      _loadHistory();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Yeniden tarama basarisiz: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Gecmis'),
        backgroundColor: const Color(0xFF1a1a2e),
        foregroundColor: Colors.white,
        actions: [
          if (_history.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.delete_outline),
              onPressed: _clearHistory,
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
            : _history.isEmpty
                ? _buildEmptyState()
                : _buildHistoryList(),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Text(
            '📋',
            style: TextStyle(fontSize: 64),
          ),
          const SizedBox(height: 16),
          const Text(
            'Henuz tarama yapilmadi',
            style: TextStyle(
              color: Colors.white70,
              fontSize: 18,
            ),
          ),
          const SizedBox(height: 8),
          const Text(
            'Taramak icin Scanner bolumune gidin',
            style: TextStyle(color: Colors.white38),
          ),
        ],
      ),
    );
  }

  Widget _buildHistoryList() {
    return RefreshIndicator(
      onRefresh: _loadHistory,
      child: ListView.builder(
        itemCount: _history.length,
        padding: const EdgeInsets.all(8),
        itemBuilder: (context, index) {
          final item = _history[index];
          return _buildHistoryItem(item);
        },
      ),
    );
  }

  Widget _buildHistoryItem(AnalysisResult item) {
    final isSafe = item.isSafe;
    final isDanger = item.isDanger;

    return Dismissible(
      key: Key(item.url),
      direction: DismissDirection.endToStart,
      background: Container(
        alignment: Alignment.centerRight,
        padding: const EdgeInsets.only(right: 16),
        color: Colors.red,
        child: const Icon(Icons.delete, color: Colors.white),
      ),
      onDismissed: (_) async {
        await widget.storageService.removeFromHistory(item.url);
        _loadHistory();
      },
      child: Card(
        color: Colors.white.withOpacity(0.1),
        margin: const EdgeInsets.symmetric(vertical: 4),
        child: InkWell(
          onTap: () => _showDetail(item),
          onLongPress: () => _rescan(item),
          borderRadius: BorderRadius.circular(12),
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                // Status Icon
                Container(
                  width: 48,
                  height: 48,
                  decoration: BoxDecoration(
                    color: isSafe
                        ? Colors.green.withOpacity(0.2)
                        : isDanger
                            ? Colors.red.withOpacity(0.2)
                            : Colors.orange.withOpacity(0.2),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Center(
                    child: Text(
                      isSafe ? '🟢' : isDanger ? '🔴' : '🟠',
                      style: const TextStyle(fontSize: 24),
                    ),
                  ),
                ),
                const SizedBox(width: 16),

                // URL Info
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        item.domain,
                        style: const TextStyle(
                          color: Colors.white,
                          fontWeight: FontWeight.w500,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 4),
                      Text(
                        _formatTime(item.timestamp),
                        style: const TextStyle(
                          color: Colors.white38,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                ),

                // Score
                Column(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    Text(
                      '${item.riskScore}',
                      style: TextStyle(
                        color: isSafe
                            ? Colors.green
                            : isDanger
                                ? Colors.red
                                : Colors.orange,
                        fontWeight: FontWeight.bold,
                        fontSize: 18,
                      ),
                    ),
                    Text(
                      isSafe ? 'Güvenli' : isDanger ? 'Tehlikeli' : 'Riskli',
                      style: const TextStyle(
                        color: Colors.white38,
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  void _showDetail(AnalysisResult item) {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF1a1a2e),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) => Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header
            Row(
              children: [
                Text(
                  item.isSafe ? '🟢' : item.isDanger ? '🔴' : '🟠',
                  style: const TextStyle(fontSize: 32),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        item.domain,
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      Text(
                        item.url,
                        style: const TextStyle(
                          color: Colors.white38,
                          fontSize: 12,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 20),

            // Stats
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceAround,
              children: [
                _buildStat('Risk', '${item.riskScore}/100',
                    item.isDanger ? Colors.red : Colors.orange),
                _buildStat('Güven', '${item.confidence}%', Colors.blue),
                _buildStat('Zaman', _formatTime(item.timestamp), Colors.white54),
              ],
            ),
            const SizedBox(height: 20),

            // Reasons
            if (item.reasons.isNotEmpty) ...[
              const Text(
                'Nedenleri:',
                style: TextStyle(color: Colors.white70),
              ),
              const SizedBox(height: 8),
              ...item.reasons.map(
                (r) => Padding(
                  padding: const EdgeInsets.symmetric(vertical: 2),
                  child: Text(
                    '• $r',
                    style: const TextStyle(color: Colors.white54),
                  ),
                ),
              ),
            ],

            const SizedBox(height: 16),

            // Actions
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: () {
                      Navigator.pop(ctx);
                      _rescan(item);
                    },
                    icon: const Icon(Icons.refresh),
                    label: const Text('Yeniden Tara'),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: Colors.white,
                      side: const BorderSide(color: Colors.white24),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: () {
                      Navigator.pop(ctx);
                      widget.storageService.removeFromHistory(item.url);
                      _loadHistory();
                    },
                    icon: const Icon(Icons.delete_outline),
                    label: const Text('Sil'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.red.withOpacity(0.2),
                      foregroundColor: Colors.red,
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStat(String label, String value, Color color) {
    return Column(
      children: [
        Text(
          label,
          style: const TextStyle(color: Colors.white38, fontSize: 12),
        ),
        const SizedBox(height: 4),
        Text(
          value,
          style: TextStyle(
            color: color,
            fontSize: 16,
            fontWeight: FontWeight.bold,
          ),
        ),
      ],
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
