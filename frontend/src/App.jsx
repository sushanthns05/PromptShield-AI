import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  LayoutDashboard, 
  Play, 
  Clock, 
  Activity, 
  Award, 
  Settings, 
  ExternalLink 
} from 'lucide-react';

import Overview from './components/Overview';
import Playground from './components/Playground';
import ApprovalsQueue from './components/ApprovalsQueue';
import EventsStream from './components/EventsStream';
import Benchmarks from './components/Benchmarks';
import SettingsModal from './components/SettingsModal';
import { api, getBackendUrl } from './api';

export default function App() {
  const [currentTab, setCurrentTab] = useState('overview'); // 'overview' | 'playground' | 'approvals' | 'events' | 'benchmarks'
  const [overview, setOverview] = useState(null);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);

  useEffect(() => {
    loadGlobalData();
  }, []);

  async function loadGlobalData() {
    setLoading(true);
    try {
      const [h, o] = await Promise.allSettled([api.getHealth(), api.getOverview()]);
      if (h.status === 'fulfilled') setHealth(h.value);
      if (o.status === 'fulfilled') setOverview(o.value);
    } catch (err) {
      console.error('Error fetching global gateway data:', err);
    } finally {
      setLoading(false);
    }
  }

  const pendingApprovalsCount = overview?.pending_approvals || 0;

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100 selection:bg-cyan-500 selection:text-black">
      {/* Top Navigation Bar */}
      <header className="sticky top-0 z-40 border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          {/* Logo & Brand */}
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => setCurrentTab('overview')}>
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center text-slate-950 shadow-lg shadow-cyan-500/20">
              <Shield className="w-5 h-5 fill-current" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-base tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-400 bg-clip-text text-transparent">
                  PromptShield AI
                </span>
                <span className="px-1.5 py-0.5 text-[10px] font-mono font-bold bg-cyan-950 text-cyan-400 rounded border border-cyan-800/50">
                  GATEWAY
                </span>
              </div>
              <span className="text-[10px] text-slate-500 block leading-none font-mono">
                Adaptive Runtime Security
              </span>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="hidden md:flex items-center gap-1 bg-slate-900/60 p-1 rounded-xl border border-slate-800/80">
            <button
              onClick={() => setCurrentTab('overview')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                currentTab === 'overview'
                  ? 'bg-slate-800 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <LayoutDashboard className="w-3.5 h-3.5" />
              Overview
            </button>

            <button
              onClick={() => setCurrentTab('playground')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                currentTab === 'playground'
                  ? 'bg-slate-800 text-cyan-400 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Play className="w-3.5 h-3.5" />
              Playground
            </button>

            <button
              onClick={() => setCurrentTab('approvals')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all relative ${
                currentTab === 'approvals'
                  ? 'bg-slate-800 text-amber-400 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Clock className="w-3.5 h-3.5" />
              Approvals
              {pendingApprovalsCount > 0 && (
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-amber-500 text-slate-950 ml-0.5">
                  {pendingApprovalsCount}
                </span>
              )}
            </button>

            <button
              onClick={() => setCurrentTab('events')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                currentTab === 'events'
                  ? 'bg-slate-800 text-purple-400 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              Audit Events
            </button>

            <button
              onClick={() => setCurrentTab('benchmarks')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                currentTab === 'benchmarks'
                  ? 'bg-slate-800 text-emerald-400 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Award className="w-3.5 h-3.5" />
              Benchmarks
            </button>
          </nav>

          {/* Right Action Utilities */}
          <div className="flex items-center gap-2.5">
            <button
              onClick={() => setIsSettingsOpen(true)}
              className="p-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors"
              title="Backend Endpoint Settings"
            >
              <Settings className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Mobile Sub-Navigation Bar */}
        <div className="md:hidden flex items-center justify-around border-t border-slate-800/60 py-2 px-2 bg-slate-950 text-xs">
          <button
            onClick={() => setCurrentTab('overview')}
            className={`px-2 py-1 rounded ${currentTab === 'overview' ? 'text-cyan-400 font-bold' : 'text-slate-400'}`}
          >
            Overview
          </button>
          <button
            onClick={() => setCurrentTab('playground')}
            className={`px-2 py-1 rounded ${currentTab === 'playground' ? 'text-cyan-400 font-bold' : 'text-slate-400'}`}
          >
            Playground
          </button>
          <button
            onClick={() => setCurrentTab('approvals')}
            className={`px-2 py-1 rounded ${currentTab === 'approvals' ? 'text-amber-400 font-bold' : 'text-slate-400'}`}
          >
            Approvals ({pendingApprovalsCount})
          </button>
          <button
            onClick={() => setCurrentTab('events')}
            className={`px-2 py-1 rounded ${currentTab === 'events' ? 'text-purple-400 font-bold' : 'text-slate-400'}`}
          >
            Events
          </button>
          <button
            onClick={() => setCurrentTab('benchmarks')}
            className={`px-2 py-1 rounded ${currentTab === 'benchmarks' ? 'text-emerald-400 font-bold' : 'text-slate-400'}`}
          >
            Benchmarks
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {currentTab === 'overview' && (
          <Overview 
            overview={overview} 
            health={health} 
            loading={loading}
            onRefresh={loadGlobalData}
            onNavigate={(tab) => setCurrentTab(tab)}
          />
        )}

        {currentTab === 'playground' && (
          <Playground 
            onEventGenerated={loadGlobalData} 
          />
        )}

        {currentTab === 'approvals' && (
          <ApprovalsQueue 
            onApprovalUpdated={loadGlobalData} 
          />
        )}

        {currentTab === 'events' && (
          <EventsStream />
        )}

        {currentTab === 'benchmarks' && (
          <Benchmarks />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 text-center text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <span>PromptShield AI • Adaptive Runtime Security Gateway for LLM Applications</span>
          <div className="flex items-center gap-4">
            <span className="text-slate-400">Endpoint: {getBackendUrl() || 'Relative /api/v1'}</span>
            <span className="text-emerald-400 font-medium">100% Tool Governance Containment</span>
          </div>
        </div>
      </footer>

      {/* Settings Modal */}
      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        onSaved={loadGlobalData}
      />
    </div>
  );
}
