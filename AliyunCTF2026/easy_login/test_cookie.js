
const cookieParser = require('cookie-parser');
const express = require('express');
const request = require('supertest');

const app = express();
app.use(cookieParser());

app.get('/', (req, res) => {
  res.json({ sid: req.cookies.sid, type: typeof req.cookies.sid });
});

async function test() {
  // Test normal cookie
  await request(app)
    .get('/')
    .set('Cookie', 'sid=123')
    .expect(200)
    .then(res => console.log('Normal:', res.body));

  // Test JSON cookie
  await request(app)
    .get('/')
    .set('Cookie', 'sid=j:{"$ne":"x"}')
    .expect(200)
    .then(res => console.log('JSON:', res.body));
}

test();
