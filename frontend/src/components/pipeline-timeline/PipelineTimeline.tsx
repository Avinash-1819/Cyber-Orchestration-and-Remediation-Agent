import AgentNode from './AgentNode';

interface Props {
  pipelineType: 'A' | 'B' | 'C';
  activeAgent: string | null;
  completedAgents: string[];
  errorAgent: string | null;
}

const pipelines = {
  A: ['MasterOrchestrator', 'DevSecOpsAgent', 'ComplianceAgent', 'ExecReportingAgent'],
  B: ['MasterOrchestrator', 'IncidentTriageAgent', 'RemediationAgent', 'ThreatIntelAgent', 'ExecReportingAgent'],
  C: ['MasterOrchestrator', 'ThreatIntelAgent', 'ExecReportingAgent']
};

export default function PipelineTimeline({ pipelineType, activeAgent, completedAgents, errorAgent }: Props) {
  const agents = pipelines[pipelineType] || pipelines.A;

  return (
    <div id="pipeline-timeline" className="glass-panel p-10 relative overflow-hidden">
      <div className="absolute top-0 left-0 w-full h-full bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:24px_24px] pointer-events-none opacity-20"></div>
      
      <h3 className="text-xl font-semibold text-white mb-12 flex items-center gap-3 relative z-10">
        <div className="w-2 h-6 bg-indigo-500 rounded-sm"></div>
        Execution Pipeline: Type {pipelineType}
      </h3>

      <div className="flex items-start justify-between relative max-w-4xl mx-auto z-10">
        {/* Connection Line */}
        <div className="absolute top-8 left-8 right-8 h-0.5 bg-slate-800 -z-10">
          <div 
            className="h-full bg-gradient-to-r from-indigo-500 via-purple-500 to-indigo-500 transition-all duration-1000 shadow-[0_0_10px_rgba(99,102,241,0.5)]" 
            style={{ 
              width: activeAgent ? `${(agents.indexOf(activeAgent) / (agents.length - 1)) * 100}%` : (completedAgents.length === agents.length ? '100%' : '0%') 
            }}
          />
        </div>

        {agents.map((agent, i) => {
          let state: 'idle' | 'active' | 'complete' | 'error' = 'idle';
          if (errorAgent === agent) state = 'error';
          else if (completedAgents.includes(agent)) state = 'complete';
          else if (activeAgent === agent) state = 'active';

          return <AgentNode key={agent} name={agent} state={state} index={i} />;
        })}
      </div>
    </div>
  );
}
