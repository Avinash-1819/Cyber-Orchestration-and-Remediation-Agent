import ReportDownloadPanel from '@/components/reports/ReportDownloadPanel';

export default function Reports() {
  return (
    <div id="reports-page" className="animate-in fade-in max-w-4xl space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Intelligence Reports</h1>
        <p className="text-slate-400">Generated artifacts and compliance documents.</p>
      </div>
      
      <div className="space-y-4">
        <ReportDownloadPanel sessionId="latest" />
      </div>
    </div>
  );
}
