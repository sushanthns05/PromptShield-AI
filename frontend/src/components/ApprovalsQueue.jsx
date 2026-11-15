import React, { useState, useEffect } from 'react';
import { 
  Clock, 
  CheckCircle2, 
  XCircle, 
  AlertCircle, 
  RefreshCw, 
  ShieldAlert, 
  UserCheck, 
  ArrowRight,
  Filter
} from 'lucide-react';
import { api } from '../api';

export default function ApprovalsQueue({ onApprovalUpdated }) {
  const [approvals, setApprovals] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [approverId, setApproverId] = useState('admin-secops');
  const [approverRole, setApproverRole] = useState('ADMIN');
  const [decisionNotes, setDecisionNotes] = useState({});
  const [submittingId, setSubmittingId] = useState(null);
  const [actionError, setActionError] = useState(null);

  useEffect(() => {
    loadApprovals();
  }, [statusFilter]);

  async function loadApprovals() {
    setLoading(true);
    setActionError(null);
    try {
      const data = await api.getApprovals({
        status: statusFilter === 'ALL' ? undefined : statusFilter,
        limit: 50,
      });
      setApprovals(data.approvals || []);
      setTotal(data.total || 0);
    } catch (err) {
      console.error('Failed to load approvals:', err);
      setActionError(err.message || 'Failed to fetch approval queue');
    } finally {
      setLoading(false);
    }
  }

  async function handleDecision(approvalId, decision) {
    setSubmittingId(approvalId);
    setActionError(null);
    try {
      const payload = {
        decision,
        approver_id: approverId,
        approver_role: approverRole,
        reason: decisionNotes[approvalId] || `Human decision: ${decision}`,
      };
      await api.submitApprovalDecision(approvalId, payload);
      await loadApprovals();
      if (onApprovalUpdated) onApprovalUpdated();
    } catch (err) {
      setActionError(err.message || `Failed to ${decision.toLowerCase()} request`);
    } finally {
      setSubmittingId(null);
    }
  }

  function getStatusBadge(status) {
    switch (status) {
      case 'PENDING':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <Clock className="w-3 h-3 animate-spin" />
            PENDING
          </span>
        );
      case 'APPROVED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3 h-3" />
            APPROVED
          </span>
        );
      case 'REJECTED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <XCircle className="w-3 h-3" />
            REJECTED
          </span>
        );
      case 'CONSUMED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            <UserCheck className="w-3 h-3" />
            CONSUMED
          </span>
        );
      case 'EXPIRED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
            <AlertCircle className="w-3 h-3" />
            EXPIRED
          </span>
        );
      default:
        return <span className="text-xs text-slate-400">{status}</span>;
    }
  }

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 rounded-2xl glass-panel">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
            Human-in-the-Loop Approval Queue
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Enforces dual authorization and separation of duties for High/Critical privileged tool invocations.
          </p>
        </div>

        {/* Approver identity switcher */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-xl">
            <span className="text-xs text-slate-400">Reviewer ID:</span>
            <input
              type="text"
              value={approverId}
              onChange={(e) => setApproverId(e.target.value)}
              className="bg-transparent text-xs text-slate-200 font-mono w-28 focus:outline-none"
            />
          </div>

          <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-xl">
            <span className="text-xs text-slate-400">Role:</span>
            <select
              value={approverRole}
              onChange={(e) => setApproverRole(e.target.value)}
              className="bg-transparent text-xs text-cyan-400 font-mono focus:outline-none"
            >
              <option value="ADMIN">ADMIN</option>
              <option value="DEVELOPER">DEVELOPER</option>
              <option value="USER">USER</option>
            </select>
          </div>

          <button
            onClick={loadApprovals}
            disabled={loading}
            className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {actionError && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-3">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{actionError}</span>
        </div>
      )}

      {/* Filter Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800/80 pb-3">
        {['ALL', 'PENDING', 'APPROVED', 'REJECTED', 'CONSUMED', 'EXPIRED'].map((st) => (
          <button
            key={st}
            onClick={() => setStatusFilter(st)}
            className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
              statusFilter === st
                ? 'bg-slate-800 text-cyan-400 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {st}
          </button>
        ))}
        <span className="ml-auto text-xs text-slate-500 font-mono">
          Showing {approvals.length} of {total}
        </span>
      </div>

      {/* Approvals Listing */}
      <div className="space-y-4">
        {approvals.length === 0 ? (
          <div className="p-12 rounded-2xl glass-panel text-center text-slate-500 text-xs">
            No approval requests found matching filter <span className="text-cyan-400 font-mono">{statusFilter}</span>.
          </div>
        ) : (
          approvals.map((req) => {
            const isPending = req.status === 'PENDING';
            const isSubmitting = submittingId === req.approval_id;

            return (
              <div
                key={req.approval_id}
                className={`p-5 rounded-2xl glass-card border transition-all ${
                  isPending
                    ? 'border-amber-500/30 hover:border-amber-500/50 bg-amber-500/[0.02]'
                    : 'border-slate-800/80'
                }`}
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="space-y-1">
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-sm font-bold text-white">
                        {req.approval_id}
                      </span>
                      {getStatusBadge(req.status)}
                      <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">
                        {req.tool_name}
                      </span>
                      <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-amber-300 font-mono">
                        {req.risk_level}
                      </span>
                    </div>

                    <div className="text-xs text-slate-400 flex flex-wrap gap-4 pt-1 font-mono">
                      <span>Requester: <span className="text-slate-200">{req.requester_id}</span> ({req.requester_role})</span>
                      <span>Created: <span className="text-slate-200">{new Date(req.created_at).toLocaleTimeString()}</span></span>
                      <span>Expires: <span className="text-slate-200">{new Date(req.expires_at).toLocaleTimeString()}</span></span>
                      {req.decided_by && (
                        <span>Decided By: <span className="text-slate-200">{req.decided_by}</span></span>
                      )}
                    </div>
                  </div>

                  {/* Actions for Pending Requests */}
                  {isPending && (
                    <div className="flex flex-col sm:flex-row items-end sm:items-center gap-3">
                      <input
                        type="text"
                        placeholder="Reviewer rationale / note..."
                        value={decisionNotes[req.approval_id] || ''}
                        onChange={(e) =>
                          setDecisionNotes({
                            ...decisionNotes,
                            [req.approval_id]: e.target.value,
                          })
                        }
                        className="bg-slate-900 border border-slate-800 text-xs text-slate-200 px-3 py-1.5 rounded-xl w-52 focus:outline-none focus:border-cyan-500"
                      />

                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleDecision(req.approval_id, 'REJECT')}
                          disabled={isSubmitting}
                          className="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 transition-colors disabled:opacity-50"
                        >
                          Reject
                        </button>
                        <button
                          onClick={() => handleDecision(req.approval_id, 'APPROVE')}
                          disabled={isSubmitting}
                          className="px-4 py-1.5 rounded-xl text-xs font-bold bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-lg shadow-emerald-500/20 transition-colors disabled:opacity-50"
                        >
                          Approve
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
