import { FileText, Download, FileJson } from 'lucide-react';

export default function ReportDownloadPanel({ sessionId }: { sessionId: string }) {
  const handleDownload = (format: string) => {
    // API call mock
    console.log(`Downloading ${format} for ${sessionId}`);
  };

  return (
    <div id="report-download-panel" className="glass-panel p-6 flex items-center justify-between">
      <div>
        <h3 className="text-lg font-semibold text-white">Execution Report</h3>
        <p className="text-sm text-slate-400">Download the comprehensive analysis report.</p>
      </div>
      <div className="flex gap-3">
        <button onClick={() => handleDownload('pdf')} className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors border border-slate-600">
          <FileText className="w-4 h-4 text-red-400" /> PDF
        </button>
        <button onClick={() => handleDownload('markdown')} className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors border border-slate-600">
          <Download className="w-4 h-4 text-blue-400" /> Markdown
        </button>
        <button onClick={() => handleDownload('json')} className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors border border-slate-600">
          <FileJson className="w-4 h-4 text-green-400" /> JSON
        </button>
      </div>
    </div>
  );
}
