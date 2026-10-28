import type { ModuleInfo, ProfileInfo, RunResult } from '../types/amf';

const API_BASE = import.meta.env.VITE_AMF_API ?? '/api';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, { ...init, headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) } });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error ?? 'AMF API request failed');
  return payload as T;
}

export function getModules() { return request<{ modules: ModuleInfo[] }>('/modules'); }
export function getProfiles() { return request<{ profiles: ProfileInfo[] }>('/profiles'); }
export function runScan(input: { target: string; allow: string[]; execute: boolean; profile: string; timeout: number }) {
  return request<{ results: RunResult[] }>('/scan', { method: 'POST', body: JSON.stringify(input) });
}
export function getHealth() { return request<{ ok: boolean; version: string; mode: string }>('/health'); }
