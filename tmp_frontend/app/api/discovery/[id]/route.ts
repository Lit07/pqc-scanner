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
    const baseDomains = new Map();
    
    // Seed spacing
    let xOffset = 30;
    let yOffset = 50;

    assets.forEach((asset: any) => {
      // Heuristic to find the root domain (e.g., api.google.com -> google.com)
      const parts = asset.hostname.split('.');
      const base = parts.length > 2 ? parts.slice(-2).join('.') : asset.hostname;
      
      if (!baseDomains.has(base)) {
        baseDomains.set(base, {
          id: `hub-${base}`,
          label: base,
          type: "hub",
          x: xOffset,
          y: yOffset
        });
        nodes.push(baseDomains.get(base));
        xOffset = (xOffset + 30) % 90; // space out distinct hubs nicely
      }

      const hubNode = baseDomains.get(base);
      const hostId = `node-${asset.hostname}`;
      
      // If it's a subdomain, create a distinct node
      if (asset.hostname !== base) {
        nodes.push({
          id: hostId,
          label: asset.hostname,
          type: "node",
          x: Math.max(10, Math.min(90, hubNode.x + (Math.random() * 20 - 10))),
          y: Math.max(10, Math.min(90, hubNode.y + (Math.random() * 20 - 10) - 15))
        });
        edges.push({ source: hubNode.id, target: hostId });
      }

      // Automatically create a Leaf node for the IP address attached to the host
      if (asset.ip && asset.ip !== "Unknown") {
        const ipId = `leaf-${asset.ip}`;
        if (!nodes.find(n => n.id === ipId)) {
          const parentId = asset.hostname === base ? hubNode.id : hostId;
          const parentNode = nodes.find(n => n.id === parentId);
          nodes.push({
            id: ipId,
            label: asset.ip,
            type: "leaf",
            x: Math.max(10, Math.min(90, parentNode.x + (Math.random() * 20 - 10))),
            y: Math.max(10, Math.min(90, parentNode.y + (Math.random() * 20 - 10) + 15))
          });
          edges.push({ source: parentId, target: ipId });
        }
      }
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
