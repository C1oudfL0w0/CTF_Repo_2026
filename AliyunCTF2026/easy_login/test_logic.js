
const crypto = require('crypto');

// Mock User DB
const users = [];
const ADMIN_PASSWORD = 'ADMIN_PASS';
users.push({ username: 'admin', password: ADMIN_PASSWORD });

async function login(body) {
  const { username, password } = body;

  if (typeof username !== 'string' || typeof password !== 'string') {
    return { status: 400, error: 'types' };
  }

  // find user
  let user = users.find(u => u.username === username);

  if (!user) {
    if (username === 'admin') {
      return { status: 403, error: 'admin reserved' };
    }
    const newUser = { username, password };
    users.push(newUser);
    user = newUser;
    console.log(`Created user: ${JSON.stringify(user)}`);
  }

  if (!user || user.password !== password) {
    return { status: 401, error: 'creds' };
  }

  return { status: 200, user };
}

// Tests
async function run() {
  console.log('--- Test 1: Normal Login ---');
  console.log(await login({ username: 'foo', password: 'bar' }));
  
  console.log('--- Test 2: Admin Login (Fail) ---');
  console.log(await login({ username: 'admin', password: 'wrong' }));

  console.log('--- Test 3: Admin Reg (Fail) ---');
  console.log(await login({ username: 'admin', password: 'newpass' }));

  console.log('--- Test 4: Unicode Normalization? ---');
  // 'admin' in some fancy font? 
  // e.g. ａｄｍｉｎ (Fullwidth DB uses exact match usually)
  console.log(await login({ username: 'ａｄｍｉｎ', password: '123' }));

  console.log('--- State of DB ---');
  console.log(users);
}

run();
