<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sirdique Storage Hub</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-4 flex items-center justify-center">
    <div class="max-w-md w-full bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-6 shadow-2xl">
        <div class="text-center">
            <h1 class="text-2xl font-bold text-indigo-400">Sirdique Storage</h1>
            <p class="text-xs text-slate-400">Cikakken Backend & Project Dashboard</p>
        </div>

        <!-- AUTH SECTION -->
        <div id="authView" class="space-y-4">
            <div class="flex border-b border-slate-800 pb-2">
                <button onclick="switchTab('login')" id="tabLogin" class="flex-1 text-center font-bold text-indigo-400">Login</button>
                <button onclick="switchTab('register')" id="tabRegister" class="flex-1 text-center text-slate-400">Sign Up</button>
            </div>

            <!-- Login Form -->
            <div id="loginForm" class="space-y-3">
                <input type="email" id="logEmail" placeholder="Email Address" class="w-full bg-slate-950 border border-slate-800 p-3 rounded-xl text-sm focus:outline-none focus:border-indigo-500">
                <input type="password" id="logPass" placeholder="Password" class="w-full bg-slate-950 border border-slate-800 p-3 rounded-xl text-sm focus:outline-none focus:border-indigo-500">
                <button onclick="loginUser()" class="w-full bg-indigo-600 hover:bg-indigo-700 p-3 rounded-xl font-medium transition text-sm">Login</button>
            </div>

            <!-- Register Form -->
            <div id="regForm" class="space-y-3 hidden">
                <input type="email" id="regEmail" placeholder="Email Address" class="w-full bg-slate-950 border border-slate-800 p-3 rounded-xl text-sm focus:outline-none focus:border-indigo-500">
                <button onclick="sendOtp()" class="w-full bg-slate-800 hover:bg-slate-700 p-3 rounded-xl font-medium transition text-xs">Tura Code (OTP) zuwa Email</button>
                <input type="text" id="regCode" placeholder="Sanya Code (Mai expire a minti 1)" class="w-full bg-slate-950 border border-slate-800 p-3 rounded-xl text-sm focus:outline-none focus:border-indigo-500">
                <input type="password" id="regPass" placeholder="Saite Sabon Password" class="w-full bg-slate-950 border border-slate-800 p-3 rounded-xl text-sm focus:outline-none focus:border-indigo-500">
                <button onclick="registerUser()" class="w-full bg-indigo-600 hover:bg-indigo-700 p-3 rounded-xl font-medium transition text-sm">Kammala Sign Up</button>
            </div>
        </div>

        <!-- DASHBOARD SECTION -->
        <div id="dashView" class="space-y-6 hidden">
            <div class="flex justify-between items-center border-b border-slate-800 pb-3">
                <span id="userDisplayEmail" class="text-xs text-indigo-300 font-mono"></span>
                <button onclick="logout()" class="text-xs text-red-400 hover:underline">Fita (Logout)</button>
            </div>

            <div class="space-y-3">
                <h2 class="text-sm font-semibold text-slate-300">Ƙirƙiri Sabon Project (Max 2)</h2>
                <input type="text" id="newProjName" placeholder="Sunan Project (Dole ya zama daban)" class="w-full bg-slate-950 border border-slate-800 p-3 rounded-xl text-sm focus:outline-none focus:border-indigo-500">
                <button onclick="createProject()" class="w-full bg-indigo-600 hover:bg-indigo-700 p-3 rounded-xl font-medium transition text-sm">New Project (+)</button>
            </div>

            <div class="space-y-3">
                <h2 class="text-sm font-semibold text-slate-300">Jerin Project ɗinka</h2>
                <div id="projectsList" class="space-y-3 max-h-60 overflow-y-auto"></div>
            </div>
        </div>
    </div>

    <script>
        function switchTab(tab) {
            if(tab === 'login') {
                document.getElementById('loginForm').classList.remove('hidden');
                document.getElementById('regForm').classList.add('hidden');
                document.getElementById('tabLogin').className = "flex-1 text-center font-bold text-indigo-400";
                document.getElementById('tabRegister').className = "flex-1 text-center text-slate-400";
            } else {
                document.getElementById('loginForm').classList.add('hidden');
                document.getElementById('regForm').classList.remove('hidden');
                document.getElementById('tabRegister').className = "flex-1 text-center font-bold text-indigo-400";
                document.getElementById('tabLogin').className = "flex-1 text-center text-slate-400";
            }
        }

        async function sendOtp() {
            const email = document.getElementById('regEmail').value;
            if(!email) return alert('Sanya email naka!');
            const res = await fetch('/api/dash/send-otp', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ email })
            });
            const data = await res.json();
            alert(data.message || data.error);
        }

        async function registerUser() {
            const email = document.getElementById('regEmail').value;
            const code = document.getElementById('regCode').value;
            const password = document.getElementById('regPass').value;
            if(!email || !code || !password) return alert('Cika duk wuraren!');
            
            const res = await fetch('/api/dash/register', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ email, code, password })
            });
            const data = await res.json();
            if(data.success) {
                alert('An yi nasara! Yanzu ka shiga Login.');
                switchTab('login');
            } else { alert(data.error); }
        }

        async function loginUser() {
            const email = document.getElementById('logEmail').value;
            const password = document.getElementById('logPass').value;
            const res = await fetch('/api/dash/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ email, password })
            });
            const data = await res.json();
            if(data.success) {
                localStorage.setItem('sirdique_email', data.email);
                loadDashboard(data.email);
            } else { alert(data.error); }
        }

        function logout() {
            localStorage.removeItem('sirdique_email');
            document.getElementById('authView').classList.remove('hidden');
            document.getElementById('dashView').classList.add('hidden');
        }

        async function loadDashboard(email) {
            document.getElementById('authView').classList.add('hidden');
            document.getElementById('dashView').classList.remove('hidden');
            document.getElementById('userDisplayEmail').innerText = email;

            const res = await fetch(`/api/dash/projects/${email}`);
            const data = await res.json();
            const list = document.getElementById('projectsList');
            list.innerHTML = '';

            if(data.projects && data.projects.length > 0) {
                data.projects.forEach(p => {
                    list.innerHTML += `
                        <div class="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
                            <p class="font-bold text-indigo-400 text-sm">${p.name}</p>
                            <p><b>Project ID:</b> <span class="font-mono bg-slate-900 p-1 rounded">${p.project_id}</span></p>
                            <p><b>API Key:</b> <span class="font-mono bg-slate-900 p-1 rounded">${p.api_key}</span></p>
                            <div class="text-slate-400 pt-1 border-t border-slate-900">
                                <p><b>Base URL:</b> https://sirdique-storage.onrender.com</p>
                                <p><b>Endpoint:</b> /api/save (POST) | /api/data (GET)</p>
                            </div>
                        </div>`;
                });
            } else {
                list.innerHTML = `<p class="text-slate-500 text-xs">Babu project da ka kirkira tukuna.</p>`;
            }
        }

        async function createProject() {
            const email = localStorage.getItem('sirdique_email');
            const name = document.getElementById('newProjName').value;
            if(!name) return alert('Sanya sunan project!');

            const res = await fetch('/api/dash/projects/create', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ email, name })
            });
            const data = await res.json();
            if(data.success) {
                document.getElementById('newProjName').value = '';
                loadDashboard(email);
            } else { alert(data.error); }
        }

        window.onload = () => {
            const savedEmail = localStorage.getItem('sirdique_email');
            if(savedEmail) loadDashboard(savedEmail);
        }
    </script>
</body>
</html>
