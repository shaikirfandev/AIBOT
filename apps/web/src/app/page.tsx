"use client";

import { useState, useEffect } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

interface Scan {
  id: string;
  target: string;
  status: string;
  findings_count: number;
  created_at: string;
}

const NAV_ITEMS = [
  "Programs",
  "Scope",
  "Assets",
  "Scans",
  "Live Agents",
  "Findings",
  "Evidence",
  "Regression",
  "Reports",
  "LLM Analysis",
  "Cost/Usage",
  "Audit Logs",
];

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState("Scans");
  const [scans, setScans] = useState<Scan[]>([]);

  useEffect(() => {
    if (activeTab === "Scans") {
      fetch(`${API}/scans`)
        .then((r) => r.json())
        .then(setScans)
        .catch(() => {});
    }
  }, [activeTab]);

  return (
    <div className="flex h-screen">
      {/* Sidebar */}
      <nav className="w-64 bg-gray-900 border-r border-gray-800 p-4">
        <h1 className="text-xl font-bold mb-6 text-green-400">
          🛡️ Bug Bounty Platform
        </h1>
        <ul className="space-y-1">
          {NAV_ITEMS.map((item) => (
            <li key={item}>
              <button
                onClick={() => setActiveTab(item)}
                className={`w-full text-left px-3 py-2 rounded text-sm ${
                  activeTab === item
                    ? "bg-green-900/50 text-green-400"
                    : "text-gray-400 hover:text-white hover:bg-gray-800"
                }`}
              >
                {item}
              </button>
            </li>
          ))}
        </ul>
      </nav>

      {/* Main */}
      <main className="flex-1 p-8 overflow-auto">
        <h2 className="text-2xl font-bold mb-6">{activeTab}</h2>

        {activeTab === "Scans" && (
          <div>
            <div className="bg-gray-900 rounded-lg border border-gray-800">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-400">
                    <th className="text-left p-3">ID</th>
                    <th className="text-left p-3">Target</th>
                    <th className="text-left p-3">Status</th>
                    <th className="text-left p-3">Findings</th>
                    <th className="text-left p-3">Created</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((s) => (
                    <tr key={s.id} className="border-b border-gray-800/50">
                      <td className="p-3 font-mono text-xs">{s.id.slice(0, 8)}</td>
                      <td className="p-3">{s.target}</td>
                      <td className="p-3">
                        <span
                          className={`px-2 py-1 rounded text-xs ${
                            s.status === "completed"
                              ? "bg-green-900/50 text-green-400"
                              : s.status === "running"
                              ? "bg-blue-900/50 text-blue-400"
                              : "bg-gray-800 text-gray-400"
                          }`}
                        >
                          {s.status}
                        </span>
                      </td>
                      <td className="p-3">{s.findings_count}</td>
                      <td className="p-3 text-gray-400">{new Date(s.created_at).toLocaleString()}</td>
                    </tr>
                  ))}
                  {scans.length === 0 && (
                    <tr>
                      <td colSpan={5} className="p-8 text-center text-gray-500">
                        No scans yet. Create a program and start a scan.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab !== "Scans" && (
          <div className="bg-gray-900 rounded-lg border border-gray-800 p-8 text-center text-gray-500">
            {activeTab} dashboard – coming in Phase 2+
          </div>
        )}
      </main>
    </div>
  );
}
