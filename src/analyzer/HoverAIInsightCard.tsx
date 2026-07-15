import React, { useEffect, useState } from "react";
import {
  File,
  Folder,
  Info,
  Link2,
  LoaderCircle,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import type { ItemRow } from "../bindings/ItemRow";
import { getHoverAiInsight } from "../agent/hoverAi";
import "./HoverAIInsightCard.css";

interface HoverAIInsightCardProps {
  item: ItemRow;
  anchorRect: DOMRect | null;
  selectedModelName?: string;
}

export const HoverAIInsightCard: React.FC<HoverAIInsightCardProps> = ({
  item,
  anchorRect,
  selectedModelName,
}) => {
  const [insight, setInsight] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();

    setLoading(true);
    setInsight(null);

    void getHoverAiInsight(item, selectedModelName, controller.signal).then(
      (text) => {
        if (active) {
          setInsight(text);
          setLoading(false);
        }
      },
    );

    return () => {
      active = false;
      controller.abort();
    };
  }, [item, selectedModelName]);

  if (!anchorRect) return null;

  // Position calculation: placement below or above anchor
  const spaceBelow = window.innerHeight - anchorRect.bottom;
  const placeAbove = spaceBelow < 220 && anchorRect.top > 220;

  const style: React.CSSProperties = {
    position: "fixed",
    left: Math.max(12, Math.min(anchorRect.left, window.innerWidth - 380)),
    top: placeAbove
      ? Math.max(8, anchorRect.top - 210)
      : Math.min(window.innerHeight - 210, anchorRect.bottom + 6),
    zIndex: 9999,
  };

  const isProtected = item.policy.tier === "protected";
  const isReview = item.policy.tier === "review_required";

  return (
    <div className="hover-ai-card" style={style} role="tooltip">
      <div className="hover-ai-header">
        <span className="hover-ai-icon">
          {item.kind === "directory" ? (
            <Folder size={16} />
          ) : item.kind === "reparse_point" ? (
            <Link2 size={16} />
          ) : (
            <File size={16} />
          )}
        </span>
        <div className="hover-ai-title">
          <strong title={item.name}>{item.name}</strong>
          <small title={item.display_path}>{item.display_path}</small>
        </div>
        <span className={`hover-policy-badge policy-${item.policy.tier}`}>
          {isProtected ? (
            <ShieldAlert size={12} />
          ) : isReview ? (
            <Info size={12} />
          ) : (
            <ShieldCheck size={12} />
          )}
          {item.policy.tier.replace("_", " ")}
        </span>
      </div>

      <div className="hover-ai-output-section">
        <div className="hover-ai-badge">
          <Sparkles className="sparkle-icon" size={13} />
          <span>AI Insight</span>
          {loading && <LoaderCircle className="spin" size={12} />}
        </div>
        <p className="hover-ai-text">
          {loading ? (
            <span className="hover-ai-loading">
              Analyzing storage item with local AI...
            </span>
          ) : (
            insight
          )}
        </p>
      </div>

      <div className="hover-ai-meta-grid">
        <div>
          <span>Allocated</span>
          <strong>{formatBytes(item.allocated_bytes)}</strong>
        </div>
        <div>
          <span>Logical</span>
          <strong>{formatBytes(item.logical_bytes)}</strong>
        </div>
        <div>
          <span>Type / Ext</span>
          <strong>{item.extension ? `.${item.extension}` : item.kind}</strong>
        </div>
        <div>
          <span>Attributes</span>
          <strong>
            {item.attributes.length > 0
              ? item.attributes.join(", ")
              : "Normal"}
          </strong>
        </div>
      </div>
    </div>
  );
};

function formatBytes(value: string | number) {
  let bytes: bigint;
  try {
    bytes = BigInt(value);
  } catch {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let divisor = 1n;
  let unit = 0;
  while (unit < units.length - 1 && bytes >= divisor * 1024n) {
    divisor *= 1024n;
    unit += 1;
  }
  if (unit === 0) return `${bytes} B`;
  const tenths = (bytes * 10n) / divisor;
  return `${tenths / 10n}.${tenths % 10n} ${units[unit]}`;
}
