import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold tracking-wide transition-colors uppercase font-mono",
  {
    variants: {
      variant: {
        default: "border border-evi-border bg-evi-panel text-evi-text",
        verified: "border border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
        malicious: "border border-red-500/30 bg-red-500/10 text-red-400 animate-pulse-ring",
        suspicious: "border border-amber-500/30 bg-amber-500/10 text-amber-400",
        benign: "border border-sky-500/30 bg-sky-500/10 text-sky-400",
        simulation: "border border-purple-500/30 bg-purple-500/10 text-purple-300",
        objection: "border border-amber-600/50 bg-amber-950/40 text-amber-300",
        outline: "border border-evi-border text-evi-muted",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
