import { useState, useEffect, createContext, useContext } from 'react';

// ==================== TYPES ====================
interface Driver {
    id: string;
    name: string;
    model: string;
    manufacturer: string;
    version: string;
    size: string;
    fileName: string;
    downloadUrl: string;
    downloadCount: number;
    createdAt: string;
}

interface User {
    id: string;
    username: string;
    displayName: string;
    role: string;
}

interface Settings {
    r2_endpoint: string;
    r2_access_key: string;
    r2_secret_key: string;
    r2_bucket: string;
    r2_public_url: string;
    r2_enabled: string;
    tool_download_url: string;
    tool_name: string;
    tool_version: string;
}

// ==================== AUTH CONTEXT ====================
const AuthContext = createContext<{
    user: User | null;
    token: string | null;
    login: (username: string, password: string) => Promise<boolean>;
    logout: () => void;
    isAuthenticated: boolean;
}>({
    user: null,
    token: null,
    login: async () => false,
    logout: () => { },
    isAuthenticated: false
});

const API_URL = '/api';

// ==================== MAIN APP ====================
function App() {
    const [user, setUser] = useState<User | null>(null);
    const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
    const [activeTab, setActiveTab] = useState<'drivers' | 'settings'>('drivers');

    useEffect(() => {
        if (token) {
            fetchUser();
        }
    }, [token]);

    const fetchUser = async () => {
        try {
            const res = await fetch(`${API_URL}/auth/me`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setUser(data.user);
            } else {
                logout();
            }
        } catch {
            logout();
        }
    };

    const login = async (username: string, password: string) => {
        try {
            const res = await fetch(`${API_URL}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            if (res.ok) {
                const data = await res.json();
                setToken(data.token);
                setUser(data.user);
                localStorage.setItem('token', data.token);
                return true;
            }
            return false;
        } catch {
            return false;
        }
    };

    const logout = () => {
        if (token) {
            fetch(`${API_URL}/auth/logout`, {
                method: 'POST',
                headers: { Authorization: `Bearer ${token}` }
            }).catch(() => { });
        }
        setToken(null);
        setUser(null);
        localStorage.removeItem('token');
    };

    const isAuthenticated = !!user && !!token;

    return (
        <AuthContext.Provider value={{ user, token, login, logout, isAuthenticated }}>
            <div className="app">
                {!isAuthenticated ? (
                    <LoginPage />
                ) : (
                    <>
                        <header className="header">
                            <div className="logo">🖨️ GoXPrint Driver Manager</div>
                            <nav className="nav">
                                <button
                                    className={`nav-btn ${activeTab === 'drivers' ? 'active' : ''}`}
                                    onClick={() => setActiveTab('drivers')}
                                >
                                    📦 Drivers
                                </button>
                                <button
                                    className={`nav-btn ${activeTab === 'settings' ? 'active' : ''}`}
                                    onClick={() => setActiveTab('settings')}
                                >
                                    ⚙️ Settings
                                </button>
                            </nav>
                            <div className="user-menu">
                                <span>👤 {user?.displayName}</span>
                                <button className="btn btn-secondary btn-sm" onClick={logout}>
                                    Logout
                                </button>
                            </div>
                        </header>
                        <main className="main">
                            {activeTab === 'drivers' && <DriversPage token={token!} />}
                            {activeTab === 'settings' && <SettingsPage token={token!} />}
                        </main>
                    </>
                )}
            </div>
        </AuthContext.Provider>
    );
}

// ==================== LOGIN PAGE ====================
function LoginPage() {
    const { login } = useContext(AuthContext);
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        const success = await login(username, password);
        if (!success) {
            setError('Username hoặc password không đúng');
        }
        setLoading(false);
    };

    return (
        <div className="login-container">
            <div className="login-card">
                <div className="login-logo">🖨️</div>
                <h1>GoXPrint Driver Manager</h1>
                <p className="login-subtitle">Đăng nhập để quản lý drivers</p>

                {error && <div className="alert alert-error">{error}</div>}

                <form onSubmit={handleSubmit}>
                    <div className="form-group">
                        <label>Username</label>
                        <input
                            type="text"
                            className="form-input"
                            value={username}
                            onChange={e => setUsername(e.target.value)}
                            placeholder="admin"
                            required
                        />
                    </div>
                    <div className="form-group">
                        <label>Password</label>
                        <input
                            type="password"
                            className="form-input"
                            value={password}
                            onChange={e => setPassword(e.target.value)}
                            placeholder="••••••••"
                            required
                        />
                    </div>
                    <button type="submit" className="btn btn-primary btn-full" disabled={loading}>
                        {loading ? '⏳ Đang đăng nhập...' : '🔐 Đăng nhập'}
                    </button>
                </form>

                <p className="login-hint">Default: admin / admin123</p>
            </div>
        </div>
    );
}

// ==================== DRIVERS PAGE ====================
interface ModelItem {
    name: string;
    selected: boolean;
    isEditing: boolean;
}

function DriversPage({ token }: { token: string }) {
    const [drivers, setDrivers] = useState<Driver[]>([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);
    const [alert, setAlert] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
    const [uploading, setUploading] = useState(false);
    const [parsing, setParsing] = useState(false);

    // Form data
    const [formData, setFormData] = useState({
        name: '', model: '', manufacturer: '', version: '', file: null as File | null
    });

    // Models management
    const [models, setModels] = useState<ModelItem[]>([]);
    const [newModelName, setNewModelName] = useState('');
    const [defaultModel, setDefaultModel] = useState('');
    const [editingIndex, setEditingIndex] = useState<number | null>(null);
    const [editValue, setEditValue] = useState('');

    // Delete range
    const [deleteFrom, setDeleteFrom] = useState('');
    const [deleteTo, setDeleteTo] = useState('');

    // Model search/filter
    const [modelSearch, setModelSearch] = useState('');
    const [minLengthFilter, setMinLengthFilter] = useState('15');
    const [defaultModelSearch, setDefaultModelSearch] = useState('');

    // Search drivers
    const [searchQuery, setSearchQuery] = useState('');

    // Edit driver
    const [editingDriver, setEditingDriver] = useState<Driver | null>(null);

    // Delete confirmation modal
    const [deleteConfirm, setDeleteConfirm] = useState<{ id: string; name: string } | null>(null);

    useEffect(() => { fetchDrivers(); }, []);

    const fetchDrivers = async () => {
        setLoading(true);
        try {
            const res = await fetch(`${API_URL}/drivers`);
            if (res.ok) setDrivers(await res.json());
        } catch (error) {
            console.error('Failed to fetch:', error);
        }
        setLoading(false);
    };

    // Parse INF from selected file
    const handleParseINF = async () => {
        if (!formData.file) {
            setAlert({ type: 'error', message: 'Vui lòng chọn file trước!' });
            return;
        }

        setParsing(true);
        setAlert(null);
        try {
            const form = new FormData();
            form.append('file', formData.file);

            const res = await fetch(`${API_URL}/admin/parse-inf`, {
                method: 'POST',
                headers: { Authorization: `Bearer ${token}` },
                body: form
            });

            if (res.ok) {
                const data = await res.json();

                // Update form with parsed data
                if (data.manufacturer && !formData.manufacturer) {
                    setFormData(prev => ({ ...prev, manufacturer: data.manufacturer }));
                }
                if (data.driverName && !formData.name) {
                    setFormData(prev => ({ ...prev, name: data.driverName }));
                }

                // Set models list with all selected by default
                const parsedModels: ModelItem[] = data.models.map((name: string) => ({
                    name,
                    selected: true,
                    isEditing: false
                }));
                setModels(parsedModels);

                // Set first model as default
                if (data.models.length > 0) {
                    setDefaultModel(data.models[0]);
                }

                setAlert({
                    type: 'success',
                    message: `Đã parse ${data.models.length} models từ ${data.infCount} file INF`
                });
            } else {
                // Try to get error message from response
                try {
                    const errorData = await res.json();
                    setAlert({ type: 'error', message: errorData.error || `Lỗi ${res.status}: ${res.statusText}` });
                } catch {
                    setAlert({ type: 'error', message: `Lỗi ${res.status}: ${res.statusText}` });
                }
            }
        } catch (error: unknown) {
            console.error('Parse INF error:', error);
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            setAlert({ type: 'error', message: `Lỗi kết nối: ${errorMessage}` });
        }
        setParsing(false);
    };

    // Add manual model
    const handleAddModel = () => {
        if (!newModelName.trim()) return;
        if (models.some(m => m.name.toLowerCase() === newModelName.toLowerCase())) {
            setAlert({ type: 'error', message: 'Model đã tồn tại!' });
            return;
        }
        setModels([...models, { name: newModelName.trim(), selected: true, isEditing: false }]);
        setNewModelName('');
    };

    // Toggle model selection
    const toggleModelSelection = (index: number) => {
        const updated = [...models];
        updated[index].selected = !updated[index].selected;
        setModels(updated);
    };

    // Delete model
    const deleteModel = (index: number) => {
        const updated = [...models];
        const deleted = updated.splice(index, 1)[0];
        setModels(updated);
        // If deleted model was default, set new default
        if (deleted.name === defaultModel && updated.length > 0) {
            setDefaultModel(updated.find(m => m.selected)?.name || updated[0].name);
        }
    };

    // Start editing model
    const startEditModel = (index: number) => {
        setEditingIndex(index);
        setEditValue(models[index].name);
    };

    // Save edited model
    const saveEditModel = (index: number) => {
        if (!editValue.trim()) return;
        const updated = [...models];
        const oldName = updated[index].name;
        updated[index].name = editValue.trim();
        setModels(updated);
        // Update default model if edited
        if (oldName === defaultModel) {
            setDefaultModel(editValue.trim());
        }
        setEditingIndex(null);
    };

    // Select/deselect all
    const toggleSelectAll = (select: boolean) => {
        setModels(models.map(m => ({ ...m, selected: select })));
    };

    // Delete models in range (1-indexed for user convenience)
    const deleteModelsInRange = () => {
        const from = parseInt(deleteFrom);
        const to = parseInt(deleteTo);

        if (isNaN(from) || isNaN(to) || from < 1 || to < from || to > models.length) {
            setAlert({ type: 'error', message: `Vui lòng nhập số hợp lệ (1-${models.length})` });
            return;
        }

        // Convert to 0-indexed
        const startIdx = from - 1;
        const endIdx = to; // to is exclusive in splice

        const updated = [...models];
        const deletedModels = updated.splice(startIdx, endIdx - startIdx);

        // Update default model if it was deleted
        if (deletedModels.some(m => m.name === defaultModel)) {
            const remaining = updated.filter(m => m.selected);
            setDefaultModel(remaining.length > 0 ? remaining[0].name : '');
        }

        setModels(updated);
        setDeleteFrom('');
        setDeleteTo('');
        setAlert({ type: 'success', message: `Đã xóa ${deletedModels.length} models (từ #${from} đến #${to})` });
    };

    // Delete models containing dot (.)
    const deleteDotModels = () => {
        const toDelete = models.filter(m => m.name.includes('.'));
        if (toDelete.length === 0) {
            setAlert({ type: 'error', message: 'Không tìm thấy model nào có dấu chấm (.)' });
            return;
        }

        const updated = models.filter(m => !m.name.includes('.'));

        // Update default model if it was deleted
        if (toDelete.some(m => m.name === defaultModel)) {
            const remaining = updated.filter(m => m.selected);
            setDefaultModel(remaining.length > 0 ? remaining[0].name : '');
        }

        setModels(updated);
        setAlert({ type: 'success', message: `Đã xóa ${toDelete.length} models có dấu chấm (${toDelete.slice(0, 3).map(m => m.name).join(', ')}${toDelete.length > 3 ? '...' : ''})` });
    };

    // Delete models shorter than specified length
    const deleteShortModels = (minLength: number) => {
        if (minLength < 1) {
            setAlert({ type: 'error', message: 'Độ dài tối thiểu phải >= 1' });
            return;
        }

        const toDelete = models.filter(m => m.name.trim().length < minLength);
        if (toDelete.length === 0) {
            setAlert({ type: 'error', message: `Không tìm thấy model nào ngắn hơn ${minLength} ký tự` });
            return;
        }

        const updated = models.filter(m => m.name.trim().length >= minLength);

        // Update default model if it was deleted
        if (toDelete.some(m => m.name === defaultModel)) {
            const remaining = updated.filter(m => m.selected);
            setDefaultModel(remaining.length > 0 ? remaining[0].name : '');
        }

        setModels(updated);
        setAlert({ type: 'success', message: `Đã xóa ${toDelete.length} models ngắn hơn ${minLength} ký tự` });
    };

    // Filter models by search query
    const filteredModels = models.filter(m =>
        modelSearch.trim() === '' || m.name.toLowerCase().includes(modelSearch.toLowerCase())
    );

    const handleUpload = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!formData.file || !formData.name || !formData.manufacturer) {
            setAlert({ type: 'error', message: 'Vui lòng điền đầy đủ thông tin!' });
            return;
        }

        setUploading(true);
        try {
            const form = new FormData();
            form.append('file', formData.file);
            form.append('name', formData.name);
            form.append('model', formData.model || 'Universal');
            form.append('manufacturer', formData.manufacturer);
            form.append('version', formData.version || '1.0');

            // Add selected models as JSON
            const selectedModels = models.filter(m => m.selected).map(m => m.name);
            form.append('models', JSON.stringify(selectedModels));
            form.append('defaultModel', defaultModel || selectedModels[0] || formData.name);

            const res = await fetch(`${API_URL}/admin/drivers`, {
                method: 'POST',
                headers: { Authorization: `Bearer ${token}` },
                body: form
            });

            if (res.ok) {
                setAlert({ type: 'success', message: 'Upload thành công!' });
                resetForm();
                setShowModal(false);
                fetchDrivers();
            } else {
                const data = await res.json();
                setAlert({ type: 'error', message: data.error || 'Upload thất bại!' });
            }
        } catch {
            setAlert({ type: 'error', message: 'Lỗi kết nối!' });
        }
        setUploading(false);
    };

    const resetForm = () => {
        setFormData({ name: '', model: '', manufacturer: '', version: '', file: null });
        setModels([]);
        setDefaultModel('');
        setNewModelName('');
    };

    // Show delete confirmation modal
    const handleDelete = (id: string, name: string) => {
        setDeleteConfirm({ id, name });
    };

    // Perform actual deletion
    const confirmDelete = async () => {
        if (!deleteConfirm) return;

        const { id } = deleteConfirm;
        setDeleteConfirm(null);

        try {
            const res = await fetch(`${API_URL}/admin/drivers/${id}`, {
                method: 'DELETE',
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                setAlert({ type: 'success', message: 'Đã xóa driver thành công!' });
                fetchDrivers();
            } else {
                const data = await res.json();
                setAlert({ type: 'error', message: data.error || 'Xóa thất bại!' });
            }
        } catch (error) {
            console.error('Delete error:', error);
            setAlert({ type: 'error', message: 'Xóa thất bại!' });
        }
    };

    // Edit driver - load data into form
    const handleEdit = (driver: Driver) => {
        setEditingDriver(driver);
        setFormData({
            name: driver.name,
            model: driver.model,
            manufacturer: driver.manufacturer,
            version: driver.version,
            file: null
        });

        // Load models if available
        const driverModels = (driver as any).models || [];
        const modelItems: ModelItem[] = driverModels.map((name: string) => ({
            name,
            selected: true,
            isEditing: false
        }));
        setModels(modelItems);
        setDefaultModel((driver as any).defaultModel || (driverModels[0] || ''));

        setShowModal(true);
    };

    // Update driver
    const handleUpdate = async () => {
        if (!editingDriver) return;

        try {
            const selectedModels = models.filter(m => m.selected).map(m => m.name);

            const res = await fetch(`${API_URL}/admin/drivers/${editingDriver.id}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify({
                    name: formData.name,
                    model: formData.model,
                    manufacturer: formData.manufacturer,
                    version: formData.version,
                    models: selectedModels,
                    defaultModel: defaultModel || selectedModels[0]
                })
            });

            if (res.ok) {
                setAlert({ type: 'success', message: 'Đã cập nhật driver!' });
                setShowModal(false);
                setEditingDriver(null);
                resetForm();
                fetchDrivers();
            } else {
                const data = await res.json();
                setAlert({ type: 'error', message: data.error || 'Cập nhật thất bại!' });
            }
        } catch (error) {
            console.error('Update error:', error);
            setAlert({ type: 'error', message: 'Cập nhật thất bại!' });
        }
    };

    const totalDownloads = drivers.reduce((sum, d) => sum + (d.downloadCount || 0), 0);
    const selectedModelsCount = models.filter(m => m.selected).length;

    // Filter drivers by search query
    const filteredDrivers = drivers.filter(driver => {
        if (!searchQuery.trim()) return true;
        const query = searchQuery.toLowerCase();
        return (
            driver.name.toLowerCase().includes(query) ||
            driver.manufacturer.toLowerCase().includes(query) ||
            driver.model.toLowerCase().includes(query) ||
            (driver as any).models?.some((m: string) => m.toLowerCase().includes(query))
        );
    });

    return (
        <div className="page">
            <div className="stats-grid">
                <div className="stat-card">
                    <div className="stat-value">{drivers.length}</div>
                    <div className="stat-label">Drivers</div>
                </div>
                <div className="stat-card">
                    <div className="stat-value">{new Set(drivers.map(d => d.manufacturer)).size}</div>
                    <div className="stat-label">Manufacturers</div>
                </div>
                <div className="stat-card">
                    <div className="stat-value">{totalDownloads.toLocaleString()}</div>
                    <div className="stat-label">Downloads</div>
                </div>
            </div>

            {alert && (
                <div className={`alert alert-${alert.type}`}>
                    {alert.type === 'success' ? '✅' : '❌'} {alert.message}
                </div>
            )}

            <div className="card">
                <div className="card-header">
                    <h2>📦 Danh sách Drivers</h2>
                    <div className="card-actions">
                        <input
                            type="text"
                            className="form-input search-input"
                            placeholder="🔍 Tìm kiếm driver..."
                            value={searchQuery}
                            onChange={e => setSearchQuery(e.target.value)}
                        />
                        <button className="btn btn-secondary btn-sm" onClick={fetchDrivers}>🔄</button>
                        <button className="btn btn-primary" onClick={() => { resetForm(); setShowModal(true); }}>➕ Upload</button>
                    </div>
                </div>

                {loading ? (
                    <div className="loading"><div className="spinner"></div> Đang tải...</div>
                ) : filteredDrivers.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-state-icon">{searchQuery ? '🔍' : '📭'}</div>
                        <p>{searchQuery ? `Không tìm thấy driver "${searchQuery}"` : 'Chưa có driver nào'}</p>
                    </div>
                ) : (
                    <div className="table-container">
                        <table className="table">
                            <thead>
                                <tr>
                                    <th>Driver</th>
                                    <th>Hãng</th>
                                    <th>Models</th>
                                    <th>Version</th>
                                    <th>Size</th>
                                    <th>Downloads</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredDrivers.map(driver => (
                                    <tr key={driver.id}>
                                        <td><strong>{driver.name}</strong></td>
                                        <td><span className="badge badge-info">{driver.manufacturer}</span></td>
                                        <td>
                                            <span className="badge badge-secondary">
                                                {(driver as any).models?.length || 0} models
                                            </span>
                                        </td>
                                        <td>v{driver.version}</td>
                                        <td>{driver.size}</td>
                                        <td>{(driver.downloadCount || 0).toLocaleString()}</td>
                                        <td className="actions">
                                            <button
                                                type="button"
                                                className="btn btn-secondary btn-sm"
                                                onClick={(e) => { e.stopPropagation(); handleEdit(driver); }}
                                                title="Sửa"
                                            >✏️</button>
                                            <button
                                                type="button"
                                                className="btn btn-secondary btn-sm"
                                                onClick={(e) => { e.stopPropagation(); navigator.clipboard.writeText(driver.downloadUrl); setAlert({ type: 'success', message: 'Đã copy URL!' }); }}
                                                title="Copy URL"
                                            >📋</button>
                                            <button
                                                type="button"
                                                className="btn btn-danger btn-sm"
                                                onClick={(e) => { e.stopPropagation(); handleDelete(driver.id, driver.name); }}
                                                title="Xóa"
                                            >🗑️</button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Upload/Edit Modal */}
            {showModal && (
                <div className="modal-overlay" onClick={() => { setShowModal(false); setEditingDriver(null); }}>
                    <div className="modal modal-lg" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>{editingDriver ? '✏️ Sửa Driver' : '📤 Upload Driver'}</h3>
                            <button className="modal-close" onClick={() => { setShowModal(false); setEditingDriver(null); }}>×</button>
                        </div>
                        <form onSubmit={editingDriver ? (e) => { e.preventDefault(); handleUpdate(); } : handleUpload}>
                            <div className="modal-body">
                                {/* File Selection - only show for new upload */}
                                {!editingDriver && (
                                    <div className="form-group">
                                        <label>File (.zip) *</label>
                                        <div className="file-row">
                                            <div className="file-input-wrapper">
                                                <div className={`file-input-label ${formData.file ? 'has-file' : ''}`}>
                                                    {formData.file ? `📦 ${formData.file.name}` : '📁 Chọn file...'}
                                                </div>
                                                <input type="file" accept=".zip,.rar,.7z" onChange={e => setFormData({ ...formData, file: e.target.files?.[0] || null })} required />
                                            </div>
                                            <button
                                                type="button"
                                                className="btn btn-secondary"
                                                onClick={handleParseINF}
                                                disabled={!formData.file || parsing}
                                            >
                                                {parsing ? '⏳ Đang parse...' : '🔍 Parse INF'}
                                            </button>
                                        </div>
                                    </div>
                                )}

                                {/* Show current file info when editing */}
                                {editingDriver && (
                                    <div className="alert alert-info">
                                        📦 File hiện tại: <strong>{editingDriver.fileName}</strong> ({editingDriver.size})
                                    </div>
                                )}

                                <div className="form-row">
                                    <div className="form-group">
                                        <label>Tên Driver *</label>
                                        <input type="text" className="form-input" placeholder="HP LaserJet Universal" value={formData.name} onChange={e => setFormData({ ...formData, name: e.target.value })} required />
                                    </div>
                                    <div className="form-group">
                                        <label>Hãng *</label>
                                        <input type="text" className="form-input" placeholder="HP, Canon, Epson..." value={formData.manufacturer} onChange={e => setFormData({ ...formData, manufacturer: e.target.value })} required />
                                    </div>
                                </div>

                                <div className="form-group">
                                    <label>Version</label>
                                    <input type="text" className="form-input" placeholder="1.0.0" value={formData.version} onChange={e => setFormData({ ...formData, version: e.target.value })} />
                                </div>
                                <div className="form-group">
                                    <label>Default Model</label>
                                    <div className="default-model-search">
                                        <input
                                            type="text"
                                            className="form-input"
                                            placeholder="🔍 Tìm nhanh model..."
                                            value={defaultModelSearch}
                                            onChange={e => setDefaultModelSearch(e.target.value)}
                                        />
                                    </div>
                                    <select
                                        className="form-input"
                                        value={defaultModel}
                                        onChange={e => setDefaultModel(e.target.value)}
                                        size={defaultModelSearch ? Math.min(5, models.filter(m => m.selected && m.name.toLowerCase().includes(defaultModelSearch.toLowerCase())).length || 1) : 1}
                                    >
                                        <option value="">-- Chọn model mặc định --</option>
                                        {models
                                            .filter(m => m.selected)
                                            .filter(m => !defaultModelSearch || m.name.toLowerCase().includes(defaultModelSearch.toLowerCase()))
                                            .map((m, i) => (
                                                <option key={i} value={m.name}>{m.name}</option>
                                            ))}
                                    </select>
                                    {defaultModelSearch && (
                                        <span className="search-result-count">
                                            {models.filter(m => m.selected && m.name.toLowerCase().includes(defaultModelSearch.toLowerCase())).length} kết quả
                                        </span>
                                    )}
                                </div>

                                {/* Models Section */}
                                <div className="models-section">
                                    <div className="models-header">
                                        <label>📋 Danh sách Models ({selectedModelsCount}/{models.length})</label>
                                        <div className="models-actions">
                                            <button type="button" className="btn btn-sm btn-secondary" onClick={() => toggleSelectAll(true)}>Chọn tất cả</button>
                                            <button type="button" className="btn btn-sm btn-secondary" onClick={() => toggleSelectAll(false)}>Bỏ chọn</button>
                                        </div>
                                    </div>

                                    {/* Add manual model */}
                                    <div className="add-model-row">
                                        <input
                                            type="text"
                                            className="form-input"
                                            placeholder="Thêm model thủ công..."
                                            value={newModelName}
                                            onChange={e => setNewModelName(e.target.value)}
                                            onKeyDown={e => e.key === 'Enter' && (e.preventDefault(), handleAddModel())}
                                        />
                                        <button type="button" className="btn btn-primary btn-sm" onClick={handleAddModel}>➕</button>
                                    </div>

                                    {/* Search and Quick Actions */}
                                    {models.length > 0 && (
                                        <div className="models-toolbar">
                                            {/* Search models */}
                                            <div className="search-models">
                                                <input
                                                    type="text"
                                                    className="form-input"
                                                    placeholder="🔍 Tìm model..."
                                                    value={modelSearch}
                                                    onChange={e => setModelSearch(e.target.value)}
                                                />
                                                {modelSearch && (
                                                    <span className="search-result">
                                                        {filteredModels.length}/{models.length}
                                                    </span>
                                                )}
                                            </div>

                                            {/* Delete models with dot (.) */}
                                            <button
                                                type="button"
                                                className="btn btn-sm btn-secondary"
                                                onClick={deleteDotModels}
                                                title="Xóa tất cả models có dấu chấm (.)"
                                            >
                                                🧹 Có dấu "."
                                            </button>
                                        </div>
                                    )}

                                    {/* Delete short models */}
                                    {models.length > 0 && (
                                        <div className="delete-range-row">
                                            <span className="delete-label">🧹 Xóa ngắn hơn:</span>
                                            <input
                                                type="number"
                                                className="form-input range-input"
                                                placeholder="15"
                                                min="1"
                                                value={minLengthFilter}
                                                onChange={e => setMinLengthFilter(e.target.value)}
                                                style={{ width: '50px' }}
                                            />
                                            <span>ký tự</span>
                                            <button
                                                type="button"
                                                className="btn btn-secondary btn-sm"
                                                onClick={() => deleteShortModels(parseInt(minLengthFilter) || 15)}
                                            >
                                                Xóa
                                            </button>
                                        </div>
                                    )}

                                    {/* Quick delete range */}
                                    {models.length > 0 && (
                                        <div className="delete-range-row">
                                            <span className="delete-label">🗑️ Xóa theo STT:</span>
                                            <input
                                                type="number"
                                                className="form-input range-input"
                                                placeholder="Từ"
                                                min="1"
                                                max={models.length}
                                                value={deleteFrom}
                                                onChange={e => setDeleteFrom(e.target.value)}
                                            />
                                            <span>-</span>
                                            <input
                                                type="number"
                                                className="form-input range-input"
                                                placeholder="Đến"
                                                min="1"
                                                max={models.length}
                                                value={deleteTo}
                                                onChange={e => setDeleteTo(e.target.value)}
                                            />
                                            <button
                                                type="button"
                                                className="btn btn-danger btn-sm"
                                                onClick={deleteModelsInRange}
                                                disabled={!deleteFrom || !deleteTo}
                                            >
                                                Xóa
                                            </button>
                                        </div>
                                    )}

                                    {/* Models list */}
                                    <div className="models-list">
                                        {models.length === 0 ? (
                                            <div className="models-empty">
                                                Nhấn "Parse INF" để tự động lấy models hoặc thêm thủ công
                                            </div>
                                        ) : filteredModels.length === 0 ? (
                                            <div className="models-empty">
                                                Không tìm thấy model nào khớp "{modelSearch}"
                                            </div>
                                        ) : (
                                            filteredModels.map((model) => {
                                                // Find original index in models array
                                                const originalIndex = models.findIndex(m => m.name === model.name);
                                                return (
                                                    <div key={originalIndex} className={`model-item ${model.selected ? 'selected' : ''} ${model.name === defaultModel ? 'is-default' : ''} ${modelSearch && model.name.toLowerCase().includes(modelSearch.toLowerCase()) ? 'highlighted' : ''}`}>
                                                        <span className="model-index">#{originalIndex + 1}</span>
                                                        <input
                                                            type="checkbox"
                                                            checked={model.selected}
                                                            onChange={() => toggleModelSelection(originalIndex)}
                                                        />
                                                        {editingIndex === originalIndex ? (
                                                            <input
                                                                type="text"
                                                                className="form-input model-edit-input"
                                                                value={editValue}
                                                                onChange={e => setEditValue(e.target.value)}
                                                                onBlur={() => saveEditModel(originalIndex)}
                                                                onKeyDown={e => e.key === 'Enter' && saveEditModel(originalIndex)}
                                                                autoFocus
                                                            />
                                                        ) : (
                                                            <span className="model-name" onDoubleClick={() => startEditModel(originalIndex)}>
                                                                {model.name}
                                                                {model.name === defaultModel && <span className="default-badge">⭐ Mặc định</span>}
                                                            </span>
                                                        )}
                                                        <div className="model-actions">
                                                            <button type="button" className="btn-icon" onClick={() => startEditModel(originalIndex)} title="Sửa">✏️</button>
                                                            <button type="button" className="btn-icon" onClick={() => deleteModel(originalIndex)} title="Xóa">🗑️</button>
                                                        </div>
                                                    </div>
                                                );
                                            })
                                        )}
                                    </div>
                                </div>
                            </div>

                            <div className="modal-footer">
                                <button type="button" className="btn btn-secondary" onClick={() => { setShowModal(false); setEditingDriver(null); }}>Hủy</button>
                                <button type="submit" className="btn btn-primary" disabled={uploading}>
                                    {editingDriver
                                        ? '💾 Lưu thay đổi'
                                        : (uploading ? '⏳ Uploading...' : '📤 Upload')
                                    }
                                </button>
                            </div>
                        </form>
                    </div>
                </div >
            )
            }
            {/* Delete Confirmation Modal */}
            {
                deleteConfirm && (
                    <div className="modal-overlay" onClick={() => setDeleteConfirm(null)}>
                        <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: '400px' }}>
                            <div className="modal-header">
                                <h3>⚠️ Xác nhận xóa</h3>
                                <button className="modal-close" onClick={() => setDeleteConfirm(null)}>×</button>
                            </div>
                            <div style={{ padding: '1rem 0' }}>
                                <p>Bạn có chắc chắn muốn xóa driver:</p>
                                <p style={{ fontWeight: 'bold', color: 'var(--accent-cyan)', margin: '0.5rem 0' }}>
                                    "{deleteConfirm.name}"
                                </p>
                                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                                    Hành động này không thể hoàn tác!
                                </p>
                            </div>
                            <div className="modal-footer">
                                <button type="button" className="btn btn-secondary" onClick={() => setDeleteConfirm(null)}>Hủy</button>
                                <button type="button" className="btn btn-danger" onClick={confirmDelete}>🗑️ Xóa</button>
                            </div>
                        </div>
                    </div>
                )
            }
        </div >
    );
}

// ==================== SETTINGS PAGE ====================
function SettingsPage({ token }: { token: string }) {
    const [settings, setSettings] = useState<Settings>({
        r2_endpoint: '',
        r2_access_key: '',
        r2_secret_key: '',
        r2_bucket: '',
        r2_public_url: '',
        r2_enabled: 'false',
        tool_download_url: '',
        tool_name: 'GoXTool',
        tool_version: '1.0.0'
    });
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [testing, setTesting] = useState(false);
    const [alert, setAlert] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);
    const [newSecretKey, setNewSecretKey] = useState('');

    useEffect(() => { fetchSettings(); }, []);

    const fetchSettings = async () => {
        setLoading(true);
        try {
            const res = await fetch(`${API_URL}/admin/settings`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) setSettings(await res.json());
        } catch (error) {
            console.error('Failed to fetch settings:', error);
        }
        setLoading(false);
    };

    const handleSave = async () => {
        setSaving(true);
        try {
            const updates = { ...settings };
            if (newSecretKey) {
                updates.r2_secret_key = newSecretKey;
            }

            const res = await fetch(`${API_URL}/admin/settings`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify(updates)
            });

            if (res.ok) {
                setAlert({ type: 'success', message: 'Settings saved!' });
                setNewSecretKey('');
                fetchSettings();
            } else {
                setAlert({ type: 'error', message: 'Save failed!' });
            }
        } catch {
            setAlert({ type: 'error', message: 'Connection error!' });
        }
        setSaving(false);
    };

    const handleTestR2 = async () => {
        setTesting(true);
        setAlert({ type: 'info', message: 'Testing R2 connection...' });

        try {
            const res = await fetch(`${API_URL}/admin/settings/test-r2`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify({
                    endpoint: settings.r2_endpoint,
                    accessKey: settings.r2_access_key,
                    secretKey: newSecretKey || settings.r2_secret_key,
                    bucket: settings.r2_bucket
                })
            });

            const data = await res.json();
            setAlert({
                type: data.success ? 'success' : 'error',
                message: data.message
            });
        } catch {
            setAlert({ type: 'error', message: 'Test failed!' });
        }
        setTesting(false);
    };

    if (loading) {
        return <div className="loading"><div className="spinner"></div> Loading...</div>;
    }

    return (
        <div className="page">
            {alert && (
                <div className={`alert alert-${alert.type}`}>
                    {alert.type === 'success' ? '✅' : alert.type === 'error' ? '❌' : 'ℹ️'} {alert.message}
                </div>
            )}

            <div className="card">
                <div className="card-header">
                    <h2>☁️ Cloudflare R2 Configuration</h2>
                </div>

                <div className="form-group">
                    <label>R2 Enabled</label>
                    <select
                        className="form-input"
                        value={settings.r2_enabled}
                        onChange={e => setSettings({ ...settings, r2_enabled: e.target.value })}
                    >
                        <option value="false">❌ Disabled (Local Storage)</option>
                        <option value="true">✅ Enabled (R2 Cloud)</option>
                    </select>
                </div>

                <div className="form-group">
                    <label>S3 Endpoint URL</label>
                    <input
                        type="text"
                        className="form-input"
                        placeholder="https://xxxxx.r2.cloudflarestorage.com"
                        value={settings.r2_endpoint}
                        onChange={e => setSettings({ ...settings, r2_endpoint: e.target.value })}
                    />
                </div>

                <div className="form-group">
                    <label>Access Key ID</label>
                    <input
                        type="text"
                        className="form-input"
                        placeholder="Access Key ID"
                        value={settings.r2_access_key}
                        onChange={e => setSettings({ ...settings, r2_access_key: e.target.value })}
                    />
                </div>

                <div className="form-group">
                    <label>Secret Access Key</label>
                    <input
                        type="password"
                        className="form-input"
                        placeholder={settings.r2_secret_key ? '••••••••' : 'Enter secret key'}
                        value={newSecretKey}
                        onChange={e => setNewSecretKey(e.target.value)}
                    />
                    <small className="form-hint">Leave empty to keep existing key</small>
                </div>

                <div className="form-group">
                    <label>Bucket Name</label>
                    <input
                        type="text"
                        className="form-input"
                        placeholder="goxprint-drivers"
                        value={settings.r2_bucket}
                        onChange={e => setSettings({ ...settings, r2_bucket: e.target.value })}
                    />
                </div>

                <div className="form-group">
                    <label>Public URL (for downloads)</label>
                    <input
                        type="text"
                        className="form-input"
                        placeholder="https://download.goxprint.com"
                        value={settings.r2_public_url}
                        onChange={e => setSettings({ ...settings, r2_public_url: e.target.value })}
                    />
                </div>

                <div className="button-group">
                    <button className="btn btn-secondary" onClick={handleTestR2} disabled={testing}>
                        {testing ? '⏳ Testing...' : '🔗 Test R2 Connection'}
                    </button>
                    <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
                        {saving ? '⏳ Saving...' : '💾 Save Settings'}
                    </button>
                </div>
            </div>

            {/* Tool Download Settings */}
            <div className="card" style={{ marginTop: '1rem' }}>
                <div className="card-header">
                    <h2>📥 Tool Download Settings</h2>
                </div>
                <p style={{ color: '#94a3b8', marginBottom: '1rem' }}>
                    Cấu hình link download phần mềm GoXTool hiển thị trên trang Remote Control
                </p>

                <div className="form-group">
                    <label>Tool Name</label>
                    <input
                        type="text"
                        className="form-input"
                        placeholder="GoXTool"
                        value={settings.tool_name || ''}
                        onChange={e => setSettings({ ...settings, tool_name: e.target.value })}
                    />
                </div>

                <div className="form-group">
                    <label>Tool Version</label>
                    <input
                        type="text"
                        className="form-input"
                        placeholder="1.0.0"
                        value={settings.tool_version || ''}
                        onChange={e => setSettings({ ...settings, tool_version: e.target.value })}
                    />
                </div>

                <div className="form-group">
                    <label>Download URL</label>
                    <input
                        type="url"
                        className="form-input"
                        placeholder="https://example.com/goxtool.exe"
                        value={settings.tool_download_url || ''}
                        onChange={e => setSettings({ ...settings, tool_download_url: e.target.value })}
                    />
                    <small style={{ color: '#64748b' }}>Link trực tiếp đến file .exe hoặc Google Drive, Dropbox...</small>
                </div>

                <div className="button-group">
                    <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
                        {saving ? '⏳ Saving...' : '💾 Lưu Cài Đặt'}
                    </button>
                </div>
            </div>
        </div>
    );
}

export default App;
