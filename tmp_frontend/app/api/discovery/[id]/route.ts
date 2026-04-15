import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";

export async function GET(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const { id } = await context.params;

  try {
    const res = await fetch(`${BACKEND_URL}/api/v1/assets`, { cache: 'no-store' });
    if (!res.ok) throw new Error("Could not fetch assets");

    const data = await res.json();
    const assets = data.assets || [];

    if (assets.length === 0) {
      return NextResponse.json({
        scan_id: id,
        nodes: [{ id: "empty", label: "No Assets Discovered", type: "hub", x: 50, y: 50 }],
        edges: []
      });
    }

    const nodes: any[] = [];
    const edges: any[] = [];

    // ── Step 1: Group assets by their root domain ──────────────────────────
    const domainGroups = new Map<string, any[]>();
    assets.forEach((asset: any) => {
      const parts = (asset.hostname || "").split('.');
      // Always take the last 2 parts as root: api.google.com → google.com
      // Edge case: bare IPs or single-part hostnames keep as-is
      const base = parts.length > 2 ? parts.slice(-2).join('.') : asset.hostname;
      if (!domainGroups.has(base)) domainGroups.set(base, []);
      domainGroups.get(base)!.push(asset);
    });

    const hubCount = domainGroups.size;

    // ── Step 2: Place hubs in a circle so they never overlap ──────────────
    // Radius scales with number of hubs; min=30 so even 1 hub isn't at center
    const hubRadius = Math.max(30, Math.min(38, 28 + hubCount * 3));
    const hubCenterX = 50;
    const hubCenterY = 50;

    let hubIndex = 0;
    domainGroups.forEach((groupAssets, base) => {
      const angleRad = (2 * Math.PI * hubIndex) / hubCount - Math.PI / 2;
      const hubX = hubCenterX + hubRadius * Math.cos(angleRad);
      const hubY = hubCenterY + hubRadius * Math.sin(angleRad);

      const hubId = `hub-${base}`;
      nodes.push({ id: hubId, label: base, type: "hub", x: hubX, y: hubY });

      // ── Step 3: Place subdomains in a smaller arc around their hub ──────
      const subdomains = groupAssets.filter(a => a.hostname !== base);
      const subRadius = 12; // distance from hub to subdomain node
      subdomains.forEach((asset, subIndex) => {
        const subAngle =
          angleRad + ((subIndex - (subdomains.length - 1) / 2) * Math.PI) / 5;
        const subX = Math.max(5, Math.min(95, hubX + subRadius * Math.cos(subAngle)));
        const subY = Math.max(5, Math.min(95, hubY + subRadius * Math.sin(subAngle)));

        const subId = `node-${asset.hostname}`;
        // Avoid duplicate nodes if the same hostname appears multiple times
        if (!nodes.find(n => n.id === subId)) {
          nodes.push({ id: subId, label: asset.hostname, type: "node", x: subX, y: subY });
          edges.push({ source: hubId, target: subId });
        }

        // Attach IP leaf to this subdomain node
        if (asset.ip && asset.ip !== "Unknown") {
          const ipId = `leaf-${asset.ip}`;
          if (!nodes.find(n => n.id === ipId)) {
            const leafAngle = subAngle + Math.PI / 8;
            const leafX = Math.max(5, Math.min(95, subX + 7 * Math.cos(leafAngle)));
            const leafY = Math.max(5, Math.min(95, subY + 7 * Math.sin(leafAngle)));
            nodes.push({ id: ipId, label: asset.ip, type: "leaf", x: leafX, y: leafY });
            edges.push({ source: subId, target: ipId });
          }
        }
      });

      // ── Step 4: Apex-level assets (hostname === base domain) get IP leaf ─
      const apexAssets = groupAssets.filter(a => a.hostname === base);
      apexAssets.forEach((asset, apexIndex) => {
        if (asset.ip && asset.ip !== "Unknown") {
          const ipId = `leaf-${asset.ip}`;
          if (!nodes.find(n => n.id === ipId)) {
            const leafAngle = angleRad + (Math.PI / 4) * (apexIndex % 4);
            const leafX = Math.max(5, Math.min(95, hubX + 10 * Math.cos(leafAngle)));
            const leafY = Math.max(5, Math.min(95, hubY + 10 * Math.sin(leafAngle)));
            nodes.push({ id: ipId, label: asset.ip, type: "leaf", x: leafX, y: leafY });
            edges.push({ source: hubId, target: ipId });
          }
        }
      });

      hubIndex++;
    });

    return NextResponse.json({ scan_id: id, nodes, edges });

  } catch (err) {
    return NextResponse.json({
      scan_id: id,
      nodes: [{ id: "err", label: "Backend Offline", type: "hub", x: 50, y: 50 }],
      edges: []
    });
  }
}
