import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { createJob, getHealth, getJob, getModules, getProfiles } from './services/api';

vi.mock('./services/api', () => ({
  createJob: vi.fn(),
  getHealth: vi.fn(),
  getJob: vi.fn(),
  getModules: vi.fn(),
  getProfiles: vi.fn(),
}));

const mocked = {
  createJob: vi.mocked(createJob),
  getHealth: vi.mocked(getHealth),
  getJob: vi.mocked(getJob),
  getModules: vi.mocked(getModules),
  getProfiles: vi.mocked(getProfiles),
};
const modules = { modules: [{ name: 'scanner/http_headers', description: 'Headers', category: 'scanner', risk: 'passive', tags: ['http'], references: [] }] };
const profiles = { profiles: [{ name: 'quick', description: 'Quick', module_count: 1 }] };

beforeEach(() => {
  vi.clearAllMocks();
  mocked.getModules.mockResolvedValue(modules);
  mocked.getProfiles.mockResolvedValue(profiles);
  mocked.getHealth.mockResolvedValue({ ok: true, version: '0.3.1', mode: 'dry-run' });
});

describe('AMF dashboard accessibility and async states', () => {
  it('exposes a live loading status and then renders labelled scan controls', async () => {
    render(<App />);

    expect(screen.getByRole('status')).toHaveTextContent('جارٍ تحميل لوحة التحكم');
    expect(await screen.findByLabelText('الهدف')).toBeInTheDocument();
    expect(screen.getByLabelText('التأكيد في القائمة البيضاء')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'بدء الفحص' })).toBeDisabled();
  });

  it('renders an alert and retry action when the initial API load fails', async () => {
    mocked.getModules.mockRejectedValueOnce(new Error('API unavailable'));
    render(<App />);

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('API unavailable');
    const retry = screen.getByRole('button', { name: 'إعادة المحاولة' });
    mocked.getModules.mockResolvedValueOnce(modules);
    await userEvent.click(retry);
    expect(await screen.findByLabelText('الهدف')).toBeInTheDocument();
  });

  it('marks an active job as busy and exposes progress semantics', async () => {
    mocked.createJob.mockResolvedValueOnce({ job: { id: 'job-12345678', status: 'queued', progress: 0, total: 1, current_module: null, results: [], error: null } });
    mocked.getJob.mockResolvedValueOnce({ job: { id: 'job-12345678', status: 'completed', progress: 1, total: 1, current_module: null, results: [], error: null } });
    render(<App />);
    await screen.findByLabelText('الهدف');
    await userEvent.type(screen.getByLabelText('الهدف'), 'https://lab.local');
    await userEvent.type(screen.getByLabelText('التأكيد في القائمة البيضاء'), 'https://lab.local');
    const button = screen.getByRole('button', { name: 'بدء الفحص' });
    await userEvent.click(button);
    await waitFor(() => expect(button).toHaveAttribute('aria-busy', 'true'));
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuemin', '0');
  });
});
