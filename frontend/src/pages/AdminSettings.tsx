import Sidebar from '../components/Sidebar';

export default function AdminSettings() {
  return (
    <div className="flex h-screen bg-[#080d1a] overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <div className="border-b border-white/[0.06] px-8 py-5">
          <h2 className="text-xl font-semibold text-white">Settings</h2>
          <p className="text-sm text-slate-500 mt-0.5">Platform configuration and administration</p>
        </div>

        <div className="px-8 py-6 space-y-4 max-w-2xl">
          <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl p-6">
            <h3 className="text-sm font-semibold text-white mb-1">Colab Inference URL</h3>
            <p className="text-xs text-slate-500 mb-3">The ngrok tunnel URL for the Colab MITRE inference model.</p>
            <div className="flex gap-3">
              <input
                type="text"
                defaultValue="https://unerased-oxymoronically-tabitha.ngrok-free.dev/run"
                readOnly
                className="flex-1 bg-[#080d1a] border border-white/[0.08] rounded-lg px-4 py-2.5 text-xs text-slate-400 font-mono focus:outline-none cursor-not-allowed opacity-60"
              />
              <span className="text-xs text-slate-600 self-center">Read-only — set via env var</span>
            </div>
          </div>

          <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl p-6">
            <h3 className="text-sm font-semibold text-white mb-1">Anthropic Fallback</h3>
            <p className="text-xs text-slate-500 mb-3">Claude model used when Colab is unreachable.</p>
            <div className="flex items-center gap-3">
              <span className="text-xs font-mono text-blue-400 bg-blue-500/10 border border-blue-500/20 px-3 py-1.5 rounded-lg">
                claude-haiku-4-5-20251001
              </span>
              <span className="inline-flex items-center gap-1.5 text-xs text-green-400 bg-green-500/10 border border-green-500/20 px-2.5 py-1 rounded-full">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
                Active
              </span>
            </div>
          </div>

          <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl p-6 opacity-50">
            <h3 className="text-sm font-semibold text-white mb-1 flex items-center gap-2">
              User Management
              <span className="text-xs text-slate-500 bg-white/[0.04] border border-white/[0.06] px-2 py-0.5 rounded-full font-normal">Coming soon</span>
            </h3>
            <p className="text-xs text-slate-500">Create and manage analyst accounts directly from the admin panel.</p>
          </div>
        </div>
      </main>
    </div>
  );
}
