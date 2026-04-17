interface StatCardProps {
  label: string;
  value: number | string;
  icon: React.ReactNode;
  color?: 'blue' | 'green' | 'amber' | 'red' | 'purple';
  trend?: string;
  subtitle?: string;
}

const colorMap = {
  blue: {
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/20',
    icon: 'text-blue-400',
    value: 'text-blue-400',
  },
  green: {
    bg: 'bg-green-500/10',
    border: 'border-green-500/20',
    icon: 'text-green-400',
    value: 'text-green-400',
  },
  amber: {
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/20',
    icon: 'text-amber-400',
    value: 'text-amber-400',
  },
  red: {
    bg: 'bg-red-500/10',
    border: 'border-red-500/20',
    icon: 'text-red-400',
    value: 'text-red-400',
  },
  purple: {
    bg: 'bg-purple-500/10',
    border: 'border-purple-500/20',
    icon: 'text-purple-400',
    value: 'text-purple-400',
  },
};

export default function StatCard({ label, value, icon, color = 'blue', trend, subtitle }: StatCardProps) {
  const c = colorMap[color];
  return (
    <div className={`bg-[#0f1629] border border-white/[0.07] rounded-xl p-5 flex items-start gap-4 hover:border-white/[0.12] transition-all duration-200`}>
      <div className={`w-11 h-11 rounded-lg ${c.bg} border ${c.border} flex items-center justify-center ${c.icon} flex-shrink-0`}>
        {icon}
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-xs text-slate-500 uppercase tracking-wider font-medium mb-1">{label}</p>
        <p className={`text-2xl font-bold ${c.value} leading-none`}>{value.toLocaleString()}</p>
        {(trend || subtitle) && (
          <p className="text-xs text-slate-500 mt-1.5">{trend || subtitle}</p>
        )}
      </div>
    </div>
  );
}
