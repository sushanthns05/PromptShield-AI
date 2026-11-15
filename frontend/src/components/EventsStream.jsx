import React, { useState, useEffect } from 'react';
import { 
  Activity, 
  RefreshCw, 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX, 
  ChevronDown, 
  ChevronUp, 
  Lock
} from 'lucide-react';
import { api } from '../api';

const CATEGORIES = [
  'ALL',
  'PROMPT_ANALYSIS',
  'DOCUMENT_SCAN',
  'TOOL_AUTHORIZATION',
  'TOOL_EXECUTION',
  'APPROVAL_WORKFLOW',
];

export default function EventsStream() {
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [expandedId, setExpandedId] = useState(null);

  useEffect(() => {
    loadEvents();
  }, [selectedCategory]);

  async function loadEvents() {
    setLoading(true);
    try {
      const data = await api.getEvents({
        category: selectedCategory,
        limit: 50,
      });
      setEvents(data.events || []);
      setTotal(data.total || 0);
    } catch (err) {
      console.error('Failed to load events:', err);
    } finally {
      setLoading(false);
    }
  }

  function getDecisionBadge(decision) {
    if (!decision) return null;
    const d = decision.toUpperCase();
    if (d === 'ALLOW' || d === 'SUCCESS' || d === 'APPROVED') {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          {d}
        </span>
      );
    }
    if (d === 'SANITIZE' || d === 'REQUIRE_APPROVAL' || d === 'PENDING') {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">
          {d}
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">
        {d}
      </span>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 rounded-2xl glass-panel">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-cyan-400" />
              Security Audit Event Stream
            </h2>
            <span className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full bg-emerald-950/80 text-emerald-300 border border-emerald-800/40">
              <Lock className="w-2.5 h-2.5" />
              Privacy Sanitized
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time tamper-evident session audit logs. Raw prompts and credentials are never stored.
          </p>
        </div>

        <button
          onClick={loadEvents}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh Stream
        </button>
      </div>

      {/* Category Filter Pills */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800/80 pb-3">
        {CATEGORIES.map((cat) => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
              selectedCategory === cat
                ? 'bg-slate-800 text-cyan-400 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {cat.replace('_', ' ')}
          </button>
        ))}
        <span className="ml-auto text-xs text-slate-500 font-mono">
          {events.length} of {total} events
        </span>
      </div>

      {/* Events Table */}
      <div className="rounded-2xl glass-panel overflow-hidden border border-slate-800">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/80 text-slate-400 font-mono border-b border-slate-800 uppercase text-[10px] tracking-wider">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Event Type</th>
                <th className="py-3 px-4">Decision</th>
                <th className="py-3 px-4">Risk</th>
                <th className="py-3 px-4">Requester</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {events.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500">
                    No security events recorded in this session yet.
                  </td>
                </tr>
              ) : (
                events.map((ev) => {
                  const isExpanded = expandedId === ev.event_id;
                  return (
                    <React.Fragment key={ev.event_id}>
                      <tr 
                        onClick={() => setExpandedId(isExpanded ? null : ev.event_id)}
                        className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                      >
                        <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                          {new Date(ev.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-3 px-4 text-slate-300 font-sans font-medium whitespace-nowrap">
                          {ev.category}
                        </td>
                        <td className="py-3 px-4 text-cyan-400 whitespace-nowrap">
                          {ev.event_type}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          {getDecisionBadge(ev.decision)}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          <span className={`${
                            ev.risk_score >= 70
                              ? 'text-rose-400'
                              : ev.risk_score >= 40
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }`}>
                            {ev.risk_score}/100
                          </span>
                        </td>
                        <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                          {ev.requester_id || 'system'}
                        </td>
                        <td className="py-3 px-4 text-right text-slate-500">
                          {isExpanded ? (
                            <ChevronUp className="w-4 h-4 inline" />
                          ) : (
                            <ChevronDown className="w-4 h-4 inline" />
                          )}
                        </td>
                      </tr>

                      {/* Expandable Metadata Row */}
                      {isExpanded && (
                        <tr className="bg-slate-950/80">
                          <td colSpan={7} className="p-4 border-t border-slate-800/80">
                            <div className="space-y-2">
                              <div className="flex items-center justify-between text-[11px] text-slate-400">
                                <span>Event UUID: <span className="text-slate-200 select-all">{ev.event_id}</span></span>
                                <span>ISO: {ev.timestamp}</span>
                              </div>
                              <pre className="p-3 bg-slate-900 rounded-xl text-xs text-slate-300 overflow-x-auto border border-slate-800 font-mono">
                                {JSON.stringify(ev.metadata || {}, null, 2)}
                              </pre>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
