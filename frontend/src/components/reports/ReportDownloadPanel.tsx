import { useState } from 'react';
import { FileText, Download, FileJson, Loader2 } from 'lucide-react';
import { reports } from '@/services/api';

const MIME_TYPES: Record<string, string> = {
  pdf: 'application/pdf',
  markdown: 'text/markdown',
  json: 'application/json',
};

export default function ReportDownloadPanel({ sessionId }: { sessionId: string }) {
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleDownload = async (format: string) => {
    if (!sessionId) return;
    setLoading(format);
    setError(null);
    try {
      const res = await reports.download(sessionId, format);
      const blob = new Blob([res.data], { type: MIME_TYPES[format] || 'application/octet-stream' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report-${sessionId}.${format === 'markdown' ? 'md' : format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (e) {
      setError('Report download failed. Please try again.');
      console.error('Report download failed:', e);
    } finally {
      setLoading(null);
    }
  };

  const buttonClass = 'flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors border border-slate-600 disabled:opacity-50 disabled:cursor-not-allowed';

  return (
    <div id="report-download-panel" className="glass-panel p-6 flex items-center justify-between">
      <div>
        <h3 className="text-lg font-semibold text-white">Execution Report</h3>
        <p className="text-sm text-slate-400">Download the comprehensive analysis report.</p>
        {error && <p className="text-sm text-red-400 mt-1">{error}</p>}
      </div>
      <div className="flex gap-3">
        <button onClick={() => handleDownload('pdf')} disabled={loading !== null || !sessionId} className={buttonClass}>
          {loading === 'pdf' ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileText className="w-4 h-4 text-red-400" />} PDF
        </button>
        <button onClick={() => handleDownload('markdown')} disabled={loading !== null || !sessionId} className={buttonClass}>
          {loading === 'markdown' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4 text-blue-400" />} Markdown
        </button>
        <button onClick={() => handleDownload('json')} disabled={loading !== null || !sessionId} className={buttonClass}>
          {loading === 'json' ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileJson className="w-4 h-4 text-green-400" />} JSON
        </button>
      </div>
    </div>
  );
}
