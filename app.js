const firebaseConfig = {
    apiKey: "AIzaSyAt5c5qywVn_71RM5iBxKNPHL_btt36B9M",
    authDomain: "nids-monitor.firebaseapp.com",
    databaseURL: "https://nids-monitor-default-rtdb.asia-southeast1.firebasedatabase.app",
    projectId: "nids-monitor",
    storageBucket: "nids-monitor.firebasestorage.app",
    messagingSenderId: "694355010000",
    appId: "1:694355010000:web:0543201b3236b95a9b19d5"
};

firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const db = firebase.database();

let isLoginMode = true;
const cols = ['timestamp', 'label', 'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss', 'service', 'sload', 'dload', 'spkts', 'dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'sjit', 'djit', 'stime', 'ltime', 'sintpkt', 'dintpkt', 'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm'];

// Khởi tạo bảng
const headerRow = document.getElementById('header-row');
if (headerRow) {
    cols.forEach(text => {
        let th = document.createElement('th');
        th.innerText = text.toUpperCase();
        headerRow.appendChild(th);
    });
}

// Xử lý giữ trạng thái đăng nhập
auth.onAuthStateChanged(user => {
    if (user) {
        showDashboard();
    } else {
        document.getElementById('auth-container').style.display = 'block';
        document.getElementById('dashboard').style.display = 'none';
    }
});

function toggleAuthMode() {
    isLoginMode = !isLoginMode;
    const btnMain = document.getElementById('btn-main');
    const title = document.getElementById('auth-title');
    const toggleLink = document.getElementById('auth-toggle');

    title.innerText = isLoginMode ? "Hệ thống giám sát NIDS" : "Đăng ký tài khoản mới";
    btnMain.innerText = isLoginMode ? "Đăng nhập" : "Tạo tài khoản";
    toggleLink.innerText = isLoginMode ? "Chưa có tài khoản? Đăng ký ngay" : "Đã có tài khoản? Quay lại Đăng nhập";
}

function handleAuth() {
    const email = document.getElementById('email').value;
    const pass = document.getElementById('password').value;

    if (!email || pass.length < 6) {
        alert("Vui lòng nhập Email và mật khẩu (tối thiểu 6 ký tự)!");
        return;
    }

    const authAction = isLoginMode 
        ? auth.signInWithEmailAndPassword(email, pass)
        : auth.createUserWithEmailAndPassword(email, pass);

    authAction.catch(err => alert("Lỗi: " + err.message));
}

function showDashboard() {
    document.getElementById('auth-container').style.display = 'none';
    document.getElementById('dashboard').style.display = 'block';
    loadData();
}

// ================= CƠ CHẾ LỌC IP (CHỐNG LAG) =================
let filterSrcValue = '';
let filterDstValue = '';

// Kỹ thuật Debounce: Chờ user ngừng gõ 300ms mới bắt đầu lọc để chống lag CPU
function debounce(func, wait) {
    let timeout;
    return function(...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}

// Hàm kiểm tra xem 1 row có khớp bộ lọc không
function isRowMatchFilters(src, dst) {
    const s = src ? String(src).toLowerCase() : '';
    const d = dst ? String(dst).toLowerCase() : '';
    return s.includes(filterSrcValue) && d.includes(filterDstValue);
}

// Lắng nghe sự kiện gõ phím vào ô lọc
const applyFilters = debounce(() => {
    filterSrcValue = document.getElementById('filter-src').value.toLowerCase().trim();
    filterDstValue = document.getElementById('filter-dst').value.toLowerCase().trim();

    // Dùng requestAnimationFrame để duyệt update DOM mượt mà
    requestAnimationFrame(() => {
        const rows = document.querySelectorAll('#data-body tr');
        rows.forEach(row => {
            const src = row.getAttribute('data-srcip');
            const dst = row.getAttribute('data-dstip');
            
            if (isRowMatchFilters(src, dst)) {
                row.style.display = ''; // Hiện
            } else {
                row.style.display = 'none'; // Ẩn
            }
        });
    });
}, 300);

document.getElementById('filter-src').addEventListener('input', applyFilters);
document.getElementById('filter-dst').addEventListener('input', applyFilters);
// =======================================================================


// ================= CƠ CHẾ CHỐNG LAG (BATCH RENDERING) =================
let dataBuffer = [];
let isRendering = false;
const MAX_DOM_ROWS = 100;

function loadData() {
    db.ref('logs').limitToLast(50).on('child_added', (snapshot) => {
        dataBuffer.push(snapshot.val());
        if (!isRendering) {
            isRendering = true;
            requestAnimationFrame(renderBuffer);
        }
    });
}

function renderBuffer() {
    if (dataBuffer.length === 0) {
        isRendering = false;
        return;
    }

    const tbody = document.getElementById('data-body');
    const fragment = document.createDocumentFragment();

    dataBuffer.forEach(data => {
        const row = document.createElement('tr');
        
        // Gắn data-attribute để phục vụ cho việc lọc IP nhanh chóng
        const currentSrcIP = data['srcip'] || '';
        const currentDstIP = data['dstip'] || '';
        row.setAttribute('data-srcip', currentSrcIP);
        row.setAttribute('data-dstip', currentDstIP);

        // Nếu data mới đổ về không khớp với IP đang được lọc -> Ẩn ngay từ đầu
        if (!isRowMatchFilters(currentSrcIP, currentDstIP)) {
            row.style.display = 'none';
        }

        if (data.label === 'attack') row.classList.add('row-attack');

        cols.forEach(col => {
            let cell = document.createElement('td');
            if (col === 'label') {
                let isAttack = data[col] === 'attack';
                cell.innerHTML = `<span class="badge ${isAttack ? 'badge-attack' : 'badge-normal'}">${isAttack ? 'ATTACK' : 'NORMAL'}</span>`;
            } else if (col === 'timestamp') {
                let date = data[col] ? new Date(data[col] * 1000) : new Date();
                cell.innerText = date.toLocaleTimeString(); 
            } else {
                let val = data[col];
                cell.innerText = typeof val === 'number' && !Number.isInteger(val) ? val.toFixed(4) : (val || '0');
            }
            row.appendChild(cell);
        });
        
        fragment.prepend(row);
    });

    dataBuffer = []; 
    tbody.prepend(fragment); 

    // Tỉa bớt node cũ
    while (tbody.rows.length > MAX_DOM_ROWS) {
        tbody.deleteRow(tbody.rows.length - 1);
    }
    
    isRendering = false;
}
// =======================================================================

function clearData() {
    if (confirm("Xóa vĩnh viễn toàn bộ lịch sử dữ liệu mạng?")) {
        db.ref('logs').remove()
            .then(() => {
                document.getElementById('data-body').innerHTML = '';
                alert("Đã dọn dẹp!");
            })
            .catch(err => alert("Lỗi: " + err.message));
    }
}

function logout() {
    auth.signOut().then(() => location.reload());
}