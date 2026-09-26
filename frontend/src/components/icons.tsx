// Inline stroke icons (16px grid) — no icon library dependency.
interface IconProps {
  size?: number
  className?: string
}

function base(size?: number) {
  return {
    width: size ?? 16,
    height: size ?? 16,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.8,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
  }
}

export function IconGauge({ size, className }: IconProps) {
  return (
    <svg {...base(size)} className={className}>
      <path d="M12 21a9 9 0 1 1 9-9" />
      <path d="M12 12l4.5-4.5" />
      <circle cx="12" cy="12" r="1.2" fill="currentColor" stroke="none" />
      <path d="M21 12a9 9 0 0 1-1.5 5" />
    </svg>
  )
}

export function IconTerminal({ size, className }: IconProps) {
  return (
    <svg {...base(size)} className={className}>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M7 9l3 3-3 3" />
      <path d="M13 15h4" />
    </svg>
  )
}

export function IconPulse({ size, className }: IconProps) {
  return (
    <svg {...base(size)} className={className}>
      <path d="M3 12h4l2.5-7 4 14 2.5-7h5" />
    </svg>
  )
}

export function IconShield({ size, className }: IconProps) {
  return (
    <svg {...base(size)} className={className}>
      <path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z" />
      <path d="M9.5 12l2 2 3.5-4" />
    </svg>
  )
}

export function IconBug({ size, className }: IconProps) {
  return (
    <svg {...base(size)} className={className}>
      <circle cx="12" cy="13" r="5" />
      <path d="M12 8V6" />
      <path d="M8.5 9.5 6.5 8M15.5 9.5l2-1.5" />
      <path d="M7 13H4M20 13h-3" />
      <path d="M8.5 16.5 6.5 18M15.5 16.5l2 1.5" />
    </svg>
  )
}

export function IconDocs({ size, className }: IconProps) {
  return (
    <svg {...base(size)} className={className}>
      <path d="M7 3h7l4 4v14H7z" />
      <path d="M14 3v4h4" />
      <path d="M10 12h5M10 16h5" />
    </svg>
  )
}

export function IconSliders({ size, className }: IconProps) {
  return (
    <svg {...base(size)} className={className}>
      <path d="M5 4v6M5 14v6M12 4v10M12 18v2M19 4v2M19 10v10" />
      <circle cx="5" cy="12" r="2" />
      <circle cx="12" cy="16" r="2" />
      <circle cx="19" cy="8" r="2" />
    </svg>
  )
}

export function IconChip({ size, className }: IconProps) {
  return (
    <svg {...base(size)} className={className}>
      <rect x="7" y="7" width="10" height="10" rx="2" />
      <path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M19 5l-2 2M5 19l2-2M19 19l-2-2" />
    </svg>
  )
}

export function IconScroll({ size, className }: IconProps) {
  return (
    <svg {...base(size)} className={className}>
      <path d="M8 21h11a2 2 0 0 0 2-2v-1H10" />
      <path d="M8 21a3 3 0 0 1-3-3V6a3 3 0 0 1 3-3h9a2 2 0 0 1 2 2v12" />
      <path d="M9 8h6M9 12h4" />
    </svg>
  )
}

export function IconHeart({ size, className }: IconProps) {
  return (
    <svg {...base(size)} className={className}>
      <path d="M12 21C7 17 3 13.5 3 9.5A4.5 4.5 0 0 1 12 7a4.5 4.5 0 0 1 9 2.5c0 4-4 7.5-9 11.5z" />
      <path d="M7 12h3l1.5-2.5L14 14l1.5-2H19" />
    </svg>
  )
}

export function IconLogout({ size, className }: IconProps) {
  return (
    <svg {...base(size)} className={className}>
      <path d="M15 4h4a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1h-4" />
      <path d="M10 8l-4 4 4 4" />
      <path d="M6 12h10" />
    </svg>
  )
}

export function IconUpload({ size, className }: IconProps) {
  return (
    <svg {...base(size)} className={className}>
      <path d="M12 16V5" />
      <path d="M8 9l4-4 4 4" />
      <path d="M4 15v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3" />
    </svg>
  )
}

export function IconSend({ size, className }: IconProps) {
  return (
    <svg {...base(size)} className={className}>
      <path d="M4 12l16-7-4.5 16L11 14l-7-2z" />
      <path d="M11 14l9-9" />
    </svg>
  )
}

export function IconLock({ size, className }: IconProps) {
  return (
    <svg {...base(size)} className={className}>
      <rect x="5" y="11" width="14" height="9" rx="2" />
      <path d="M8 11V8a4 4 0 0 1 8 0v3" />
      <circle cx="12" cy="15.5" r="1.4" />
    </svg>
  )
}
