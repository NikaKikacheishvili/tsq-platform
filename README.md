# TSQ-style platform starter

## გაშვება
1. დააყენე Node.js 20+.
2. ამ საქაღალდეში გაუშვი: `npm install`
3. გაუშვი: `JWT_SECRET="შენი-გრძელი-საიდუმლო" npm start`
4. გახსენი `http://localhost:3000`

ეს არის რეალური backend-იანი starter: რეგისტრაცია, login, cookie session, SQLite, referral link, ტრანზაქციების ისტორია და withdrawal request.

ფულადი დეპოზიტის რეალური მიღება/გატანა შეგნებულად არ არის გაყალბებული: საჭიროა გადახდის პროვაიდერის ოფიციალური API და server-to-server დადასტურება. პაროლები ინახება hash-ით, არა plaintext-ად.
