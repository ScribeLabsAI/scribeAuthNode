// import { describe, expect, test } from '@jest/globals';
// import * as dotenv from 'dotenv';
// import { readFile } from 'node:fs/promises';
// import { ScribeAuth } from '../dist/auth/scribeAuth.js';

// dotenv.config();

// const content = await readFile('./tests/.env', 'utf8');
// const buffer = Buffer.from(content);
// const data = dotenv.parse(buffer);
// console.log(data);
// const clientId = data['CLIENT_ID']!;
// const username = data['USER']!;
// const password = data['PASSWORD']!;
// const newPassword = data['NEW_PASSWORD']!;
// const access = new ScribeAuth(clientId);

// describe('Update password', () => {
//   test(`Successful`, async () => {
//     const response = await access.changePassword(username, password, newPassword);
//     console.log(response);
//     expect(clientId).toBeDefined();
//   });
// });
