import React, { useState } from 'react';
import { X, Server, CheckCircle2, AlertCircle, RefreshCw } from 'lucide-react';
import { getBackendUrl, setBackendUrl, api } from '../api';

export default function SettingsModal({ isOpen, onClose, onSaved }) {
  const [url, setUrl] = useState(getBackendUrl() || 'http://localhost:8000');
  const [testing, setTesting] = useState(false);
  const [testStatus, setTestStatus] = useState(null); // { success: boolean, message: string }

  if (!isOpen) return null;

  async function handleTest() {
    setTesting(true);
    setTestStatus(null);
    try {
      setBackendUrl(url);
      const health = await api.getHealth();
      setTestStatus({
        success: true,
        message: `Connected successfully! Status: ${health.status}, Version: ${health.version || '1.0.0'}`,
      });
    } catch (err) {
      setTestStatus({
        success: false,
        message: `Connection failed: ${err.message}`,
      });
    } finally {
      setTesting(false);
    }
  }

  function handleSave() {
    setBackendUrl(url);
    if (onSaved) onSaved();
    onClose();
  }

  function handleReset() {
    setUrl(window.location.hostname === 'localhost' ? 'http://localhost:8000' : '');
    setBackendUrl('');
    setTestStatus(null);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-2xl glass-panel p-6 border border-slate-700 shadow-2xl space-y-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-white font-bold text-base">
            <Server className="w-5 h-5 text-cyan-400" />
            Backend Connection Settings
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed">
          Configure the PromptShield AI FastAPI backend endpoint URL. Use this to switch between local development and your deployed Render backend service.
        </p>

        <div className="space-y-2">
          <label className="text-xs font-semibold text-slate-300">Backend API URL</label>
          <input
            type="text"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              setTestStatus(null);
            }}
            placeholder="https://your-service.onrender.com or http://localhost:8000"
            className="w-full bg-slate-900 border border-slate-700 text-xs text-slate-100 p-3 rounded-xl font-mono focus:outline-none focus:border-cyan-500"
          />
        </div>

        {testStatus && (
          <div className={`p-3 rounded-xl text-xs flex items-start gap-2.5 ${
            testStatus.success 
              ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300' 
              : 'bg-rose-500/10 border border-rose-500/30 text-rose-300'
          }`}>
            {testStatus.success ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            )}
            <span className="leading-tight">{testStatus.message}</span>
          </div>
        )}

        <div className="flex items-center justify-between pt-2">
          <button
            onClick={handleReset}
            className="text-xs text-slate-400 hover:text-slate-200 underline"
          >
            Reset to Default
          </button>

          <div className="flex items-center gap-2">
            <button
              onClick={handleTest}
              disabled={testing || !url}
              className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors flex items-center gap-1.5 disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${testing ? 'animate-spin' : ''}`} />
              Test
            </button>

            <button
              onClick={handleSave}
              className="px-4 py-2 rounded-xl text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-colors shadow-lg shadow-cyan-500/20"
            >
              Save Endpoint
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
