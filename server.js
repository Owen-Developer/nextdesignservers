const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');
const app = express();
const PORT = process.env.PORT || 3000;
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
require('dotenv').config();
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const e = require('express');
const stripe = require("stripe")(process.env.pooja_STRIPE_SECRET_KEY);

const accessKey = process.env.pooja_ACCESS_KEY;

const poojaDb = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.POOJA_DB_NAME,
    port: process.env.PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});
const cadgolfDb = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.cadgolf_DB_NAME,
    port: process.env.PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});
const nextdesignDb = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.next_DB_NAME,
    port: process.env.PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const store = new MySQLStore({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.POOJA_DB_NAME,
    port: process.env.PORT // 24642 or 3306
});

const allowedOrigins = [
    'http://localhost:3000',
    'https://nextdesignwebsite.com',
    'https://cadgolfperformance.com',
    'https://poojasbeautysalon.com'
];
app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);

        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('CORS not allowed from this origin'));
        }
    },
    credentials: true
}));

function decideDb(req, res, next){
    const origin = req.headers.origin;

    if(origin == "https://poojasbeautysalon.com"){
        req.db = poojaDb;
    } else if(origin == "https://cadgolfperformance.com"){
        req.db = cadgolfDb;
    } else if(origin == "https://nextdesignwebsite.com"){
        req.db = nextdesignDb;
    }

    next();
}
app.use(decideDb);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);

app.use(session({
    store,
    secret: process.env.pooja_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, 
        //domain: '.poojasbeautysalon.com',
        secure: true,       // HTTPS only
        sameSite: 'none'    // allow cross-site cookies
    }
}));

app.use(express.static('docs'));




/*//////////////////////////////////// GLOBAL STUFF /////////////////////////////////*/
function isValidEmail(email){
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}
/*///////////////////////////////////////////////////////////////////////////////////*/



/*//////////////////////////////////// POOJAS BEAUTY /////////////////////////////////*/
async function poojaSendEmail(userEmail, code) {
    const dataToSend = { reciever: userEmail, text: `${code}`, service: 'nextdesign' };
    try {
        const response = await fetch('https://email-sender-lkex.vercel.app/api/send-email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json', 
            },
            body: JSON.stringify(dataToSend), 
        });

        if (!response.ok) {
            const errorData = await response.json();
            console.error('Error:', errorData.error);
            return;
        }
    } catch (error) {
        console.error('Error posting data:', error);
    }
}
function poojaSendClientEmail(userEmail, date, time, email, message, services, price){ 
    poojaSendEmail(userEmail, `<p>Hello, a booking was made for poojasbeautysalon for: ${date}, ${time}\n\nEmail: ${email}\n\nMessage: ${message}\n\nServices: ${services.replace(/,,/g, ", ")}\n\nPrice: ${price}</p>`);
}
function poojaSendClientFree(userEmail, date, time, email, message, code, services) { 
    poojaSendEmail(userEmail, `<p>Hello, a booking was made for poojasbeautysalon for: ${date}, ${time}\n\nEmail: ${email}\n\nMessage: ${message}\n\nVoucher code: ${code}\n\nServices: ${services.replace(/,,/g, ", ")}\n\nThis booking was made using a voucher.</p>`);
}
function poojaSendClientStore(userEmail, date, time, email, message, services) { 
    poojaSendEmail(userEmail, `<p>Hello, a booking was made for poojasbeautysalon for: ${date}, ${time}\n\nEmail: ${email}\n\nMessage: ${message}\n\nServices: ${services.replace(/,,/g, ", ")}\n\nThis booking it to be paid in store.</p>`);
}
function poojaSendClientGiftRequest(email, price){
    poojaSendEmail(process.env.pooja_ADMIN_EMAIL, `<p>Hello, a gift card purchase was made for poojas beauty salon with the email: ${email}, for £${price}.</p>`);

}
function poojaSendUserVoucher(userEmail, Giftcode) {  
    poojaSendEmail(userEmail, `<p>Hello, thank you for purchasing a voucher at Pooja's Beauty Salon. Use this code at checkout: ${Giftcode}</p>`);
}
function poojaSendUserEmail(userEmail, date, time, link) {
    poojaSendEmail(userEmail, `<p>Hello, you made a booking for poojasbeautysalon: ${date}, ${time}\n\nCancel anytime with this link: ${link}</p>`);
}
function poojaSendUserFree(userEmail, date, time, link){
    poojaSendEmail(userEmail, `<p>Hello, you made a booking for poojasbeautysalon: ${date}, ${time}\n\nCancel anytime with this link: ${link}</p>`);
}
function poojaSendApologyEmail(userEmail, date){
    poojaSendEmail(userEmail, `<p>Sorry, your booking for poojasbeautysalon on ${date} has been cancelled due to a schedule change. Please and rebook at your convenience.</p>`);
}
function poojaSendClientForm(infoEmail, name, email, phone, message){
    poojaSendEmail(infoEmail, `<p>Hello, a contact form was submitted from Pooja's Beauty Salon's website:\n\nName: ${name}\n\nEmail: ${email}\n\nPhone Number: ${phone}\n\nMessage: ${message}</p>`);
}
function poojaSendClientDelete(date, reason){  
    poojaSendEmail(process.env.pooja_ADMIN_EMAIL, `<p>A booking for Pooja's Beauty Salon was cancelled for: ${date}\n\nReason: ${reason}</p>`);
}
function poojaSendUserDelete(userEmail, date, reason){  
    poojaSendEmail(userEmail, `<p>Your booking for Pooja's Beauty Salon was cancelled for: ${date}\n\nReason: ${reason}</p>`);
}
function poojaGenerateNumber(){
    return crypto.randomBytes(5).toString('hex'); 
}
function poojaRequireAdmin(req, res, next){
    if(!req.session.admin && false){
        return res.json({ message: 'Unauth' });
    }
    next();
}



app.post("/pooja/api/book-appointment", async (req, res) => {
    const date = req.body.date;
    const time = req.body.time;
    const email = req.body.email;
    const message = req.body.message;
    const code = req.body.code;
    const services = req.body.services;
    const price = req.body.price;
    const type = req.body.type;
    const applied = req.body.applied;
    const timeTaken = req.body.totalTime;

    if(!isValidEmail(email)){
        return res.json({ message: 'failed' });
    }

    const cancelCode = poojaGenerateNumber();
    const cancelLink = url + "/bookings.html?cancel=" + cancelCode;

    let paymentStr = "Not Paid Yet (instore)";
    if(req.body.inStore == "paid" && req.session.admin){
        paymentStr = "Paid in Store";
    } else if(req.body.inStore == "unpaid" && req.session.admin){
        paymentStr = "Not Paid Yet";
    }

    if(req.body.inStore == "paid" || req.body.inStore == "unpaid" || req.body.inStore == "true"){
        let values = [];
        let emailFinish;
        for(let i = 0; i < timeTaken; i++){
            let finishTime = null;
            let minNum = Number(time.slice(3, 5));
            let newTime = time.slice(0, 3) + String(minNum + (15 * i));
            if(minNum + (15 * i) > 45){
                let exceed = Math.floor((minNum + (15 * i)) / 60);
                newTime = String(Number(time.slice(0, 2)) + exceed) + ":" + String((minNum + (15 * i)) - (60 * exceed));
                if(String((minNum + (15 * i)) - (60 * exceed)) == "0"){
                    newTime = newTime + "0";
                }
            }
            let rowType = "filler";
            if(i == 0){
                rowType = "user";
                newTime = time;

                let lastTime = time.slice(0, 3) + String(minNum + (15 * (timeTaken - 1)));
                if(minNum + (15 * (timeTaken - 1)) > 45){
                    let exceed = Math.floor((minNum + (15 * (timeTaken - 1))) / 60);
                    lastTime = String(Number(time.slice(0, 2)) + exceed) + ":" + String((minNum + (15 * (timeTaken - 1))) - (60 * exceed));
                    if(String((minNum + (15 * i)) - (60 * exceed)) == "0"){
                        lastTime = lastTime + "0";
                    }
                }
                finishTime = lastTime.slice(0, 3) + String(Number(lastTime.slice(3)) + 15);
                if((Number(lastTime.slice(3)) + 15) == 60){
                    finishTime = String(Number(lastTime.slice(0, 2)) + 1) + ":00";
                }
                emailFinish = finishTime;
            }
            values.push([date, newTime, email, message, code, services, rowType, price, cancelCode, paymentStr, timeTaken, finishTime]);
        }

        poojaSendClientStore(process.env.pooja_ADMIN_EMAIL, date, time + " - " + emailFinish, email, message, services);
        poojaSendUserFree(email, date, time + " - " + emailFinish, cancelLink);

        const insertQuery = "insert into bookings (booking_date, booking_time, email, message, coupon_code, services, booking_type, price, cancel_code, payment_status, time_taken, finish_time) values ?";
        req.db.query(insertQuery, [values], (err, result) => {
            if(err){
                console.error("Error updating booking: ", err);
                return res.json({ message: 'failed' });
            }

            return res.json({ message: 'success' });
        });
    } else if(applied){
        req.db.query("select * from codes where coupon_code = ?", [code], (err, result) => {
            if(err){
                console.error("Error selecting codes: " + err);
            }

            let values = [];
            let emailFinish;
            for(let i = 0; i < timeTaken; i++){
                let finishTime = null;
                let minNum = Number(time.slice(3, 5));
                let newTime = time.slice(0, 3) + String(minNum + (15 * i));
                if(minNum + (15 * i) > 45){
                    let exceed = Math.floor((minNum + (15 * i)) / 60);
                    newTime = String(Number(time.slice(0, 2)) + exceed) + ":" + String((minNum + (15 * i)) - (60 * exceed));
                    if(String((minNum + (15 * i)) - (60 * exceed)) == "0"){
                        newTime = newTime + "0";
                    }
                }
                let rowType = "filler";
                if(i == 0){
                    rowType = "user";
                    newTime = time;

                    let lastTime = time.slice(0, 3) + String(minNum + (15 * (timeTaken - 1)));
                    if(minNum + (15 * (timeTaken - 1)) > 45){
                        let exceed = Math.floor((minNum + (15 * (timeTaken - 1))) / 60);
                        lastTime = String(Number(time.slice(0, 2)) + exceed) + ":" + String((minNum + (15 * (timeTaken - 1))) - (60 * exceed));
                        if(String((minNum + (15 * i)) - (60 * exceed)) == "0"){
                            lastTime = lastTime + "0";
                        }
                    }
                    finishTime = lastTime.slice(0, 3) + String(Number(lastTime.slice(3)) + 15);
                    if((Number(lastTime.slice(3)) + 15) == 60){
                        finishTime = String(Number(lastTime.slice(0, 2)) + 1) + ":00";
                    }
                    emailFinish = finishTime;
                }
                values.push([date, newTime, email, message, code, services, rowType, price, cancelCode, "Paid Online (Voucher)", timeTaken, finishTime]);
            }

            let newValue = result[0].value - Number(price.slice(1));
            const insertQuery = "insert into bookings (booking_date, booking_time, email, message, coupon_code, services, booking_type, price, cancel_code, payment_status, time_taken, finish_time) values ?";
            req.db.query(insertQuery, [values], (err, result) => {
                if(err){
                    console.error("Error updating booking: ", err);
                    return res.json({ message: 'failed' });
                }

                const updateValueQuery = "update codes set value = ? where coupon_code = ?";
                req.db.query(updateValueQuery, [newValue, code], (err, result) => {
                    if(err){
                        console.error("Error updating gift value: " + err);
                    }

                    poojaSendClientFree(process.env.pooja_ADMIN_EMAIL, date, time + " - " + emailFinish, email, message, code, services);
                    poojaSendUserFree(email, date, time + " - " + emailFinish, cancelLink);
                    return res.json({ message: 'success' });
                });
            });
        });
    } else {
        async function payProduct(){
            let productPriceMap = {
                "product_1": "price_1RyRP0IO0M0lx6yNE3OdZKoT", // chin
                "product_2": "price_1RyROxIO0M0lx6yNJGxBDUwe", // chin
                "product_3": "price_1RyROvIO0M0lx6yNAlBjdRRi", // chin
                "product_4": "price_1RyROsIO0M0lx6yNrRPjtKhg", // chin
                "product_5": "price_1RyROpIO0M0lx6yN9QJc41i1", // chin
                "product_6": "price_1RyROmIO0M0lx6yN9hoXUPOS", // chin
                "product_7": "price_1RyROjIO0M0lx6yNtFgyD9DT", // chin
                "product_8": "price_1RyROhIO0M0lx6yNmkLp8sw4", // chin
                "product_9": "price_1RyROeIO0M0lx6yNyNY3F3Ov", // chin
                "product_10": "price_1RyROaIO0M0lx6yNGCh5dGux", // chin
                "product_11": "price_1RyROXIO0M0lx6yN4MT75Wv0", // chin
                "product_12": "price_1RyROUIO0M0lx6yNpf14ZlKX", // chin
                "product_13": "price_1RyRORIO0M0lx6yNZJnwMKki", // chin
                "product_14": "price_1RyROOIO0M0lx6yNRMic1pPU", // chin
                "product_15": "price_1RyROMIO0M0lx6yNaBDKAYg4", // chin
                "product_16": "price_1RyROJIO0M0lx6yNpkCULOsm", // chin
                "product_17": "price_1RyROHIO0M0lx6yN49hhI8KS", // chin
                "product_18": "price_1RyRODIO0M0lx6yNrgGabamU", // chin
                "product_19": "price_1RyROAIO0M0lx6yNpDH0wWjQ", // chin
                "product_20": "price_1RyRO8IO0M0lx6yNSurTWaJW", // chin
                "product_21": "price_1RyRO0IO0M0lx6yNYeCpvX6n", // chin
                "product_22": "price_1RyRNyIO0M0lx6yNUGKkjTVe", // chin
                "product_23": "price_1RyRNwIO0M0lx6yNjNLHpHYh", // chin
                "product_24": "price_1RyRNtIO0M0lx6yNfQqJXTAl", // chin
                "product_25": "price_1RyRNqIO0M0lx6yN8bUU0jyi", // chin
                "product_26": "price_1RyRNoIO0M0lx6yNMU7fHoy1", // chin
                "product_27": "price_1RyRNlIO0M0lx6yNrgAg9Tr7", // chin
                "product_28": "price_1RyRNjIO0M0lx6yNKx2IGr8f", // chin
                "product_29": "price_1RyRNfIO0M0lx6yNrjqpFKPy", // chin
                "product_30": "price_1RyRNcIO0M0lx6yNFGGDqQk6", // chin
                "product_31": "price_1RyRNaIO0M0lx6yNXHgfnWFC", // chin
                "product_32": "price_1RyRNXIO0M0lx6yNHbglizS5", // chin
                "product_33": "price_1RyRNUIO0M0lx6yNuSkpLgTe", // chin
                "product_34": "price_1RyRNRIO0M0lx6yNiF9mlm5j", // chin
                "product_35": "price_1RyRNPIO0M0lx6yN8fm8s49u", // chin
                "product_36": "price_1RyRNMIO0M0lx6yNJwEmrMUG", // chin
                "product_37": "price_1RyRNJIO0M0lx6yNMSx7ZrDD", // chin
                "product_38": "price_1RyRNGIO0M0lx6yNKIj7nMNQ", // chin
                "product_39": "price_1RyRNEIO0M0lx6yNolAZz1QV", // chin
                "product_40": "price_1RyRNCIO0M0lx6yNGVd0AZRf", // chin
                "product_41": "price_1RyRN3IO0M0lx6yNOXvvzkFn", // chin
                "product_42": "price_1RyRN0IO0M0lx6yNrssAcH4k", // chin
                "product_43": "price_1RyRMxIO0M0lx6yN8xx4sDbj", // chin
                "product_44": "price_1RyRMvIO0M0lx6yNgiUHgsiN", // chin
                "product_45": "price_1RyRMtIO0M0lx6yN3bb6cLX8", // chin
                "product_46": "price_1RyRMqIO0M0lx6yNNVAOdGBr", // chin
                "product_47": "price_1RyRMoIO0M0lx6yNg8OsX9vc", // chin
                "product_48": "price_1RyRLUIO0M0lx6yNFZFNnXE2", // chin
                "product_49": "price_1RyRLSIO0M0lx6yNcowTD85N", // chin
                "product_50": "price_1RyRLOIO0M0lx6yNDPxmDdzX", // chin
                "product_51": "price_1RyRLHIO0M0lx6yNH16Y24U9", // chin
                "product_52": "price_1RyRLEIO0M0lx6yNeHvL0YsT", // chin
                "product_53": "price_1RyRLAIO0M0lx6yNoUmdHkoK", // chin
                "product_54": "price_1RyRL7IO0M0lx6yNfgaeNqXO", // chin
                "product_55": "price_1RyRL5IO0M0lx6yNPv4syCUA", // chin
                "product_56": "price_1RyRL2IO0M0lx6yNi9WknLNb", // chin
                "product_57": "price_1RyRKzIO0M0lx6yN6KFqnU3Z", // chin
                "product_58": "price_1RyRKxIO0M0lx6yNGiiME31M", // chin
                "product_59": "price_1RyRKvIO0M0lx6yNEFm6uClD", // chin
                "product_60": "price_1RyRKsIO0M0lx6yN7Y9l10vG", // chin
                "product_61": "price_1RyRKjIO0M0lx6yNrTklJNyN", // chin
                "product_62": "price_1RyRKhIO0M0lx6yNJ7e9gUJ7", // chin
                "product_63": "price_1RyRKeIO0M0lx6yNV3L9Q96W", // chin
                "product_64": "price_1RyRKbIO0M0lx6yNjPHsUNFh", // chin
                "product_65": "price_1RyRKOIO0M0lx6yN8jtMnPOj", // chin
                "product_66": "price_1RyRKKIO0M0lx6yNbYzWbTxT", // chin
                "product_67": "price_1RyRKIIO0M0lx6yNLyEm9Nfq", // chin
                "product_68": "price_1RyRKEIO0M0lx6yN5kyU4egj", // chin
                "product_69": "price_1RyRK7IO0M0lx6yNN1ct1QFE", // chin
                "product_70": "price_1RyRK0IO0M0lx6yNqD78dOQk", // chin
                "product_71": "price_1RyRJuIO0M0lx6yNSxPneFUZ", // chin
                "product_72": "price_1RyRJpIO0M0lx6yNjW66246Q", // chin
                "product_73": "price_1RyRJmIO0M0lx6yNkedPgIqs", // chin
                "product_74": "price_1RyRJiIO0M0lx6yNopN1Y2Sa", // chin
                "product_75": "price_1RyQL2IO0M0lx6yN15TOyJlA", // chin
                "product_76": "price_1RyQKyIO0M0lx6yN7SbpXW7N", // chin
                "product_77": "price_1RyQKwIO0M0lx6yNWB3aMQoG", // chin
                "product_78": "price_1RyQKiIO0M0lx6yNvuSE0ULy", // chin
                "product_79": "price_1RyQKgIO0M0lx6yNY5Ors0VW", // chin
                "product_80": "price_1RyQK4IO0M0lx6yNtrILrJma", // chin
                "product_81": "price_1RyQJsIO0M0lx6yN5Cc47If3", // chin
                "product_82": "price_1RyQJmIO0M0lx6yN0kgtF6H4", // chin
                "product_83": "price_1RyQHLIO0M0lx6yNxryjcybQ", // chin
            };
            /*
            let productPriceMap = {
                "product_1": "price_1RyGREIO0M0lx6yNWh1fONaP", // chin
                "product_2": "price_1RyGUIIO0M0lx6yN1DREpeSw", // chin
                "product_3": "price_1RyGUqIO0M0lx6yNTotKK3v3", // chin
                "product_4": "price_1RyGV8IO0M0lx6yNpGZkVsq0", // chin
                "product_5": "price_1RyGVhIO0M0lx6yNXpiJMasP", // chin
                "product_6": "price_1RyGVxIO0M0lx6yNbea3WkaJ", // chin
                "product_7": "price_1RyGWeIO0M0lx6yN5o9Op4oQ", // chin
                "product_8": "price_1RyGXQIO0M0lx6yNYNnDiYiH", // chin
                "product_9": "price_1RyGXhIO0M0lx6yNqpaOYeBX", // chin
                "product_10": "price_1RyGY2IO0M0lx6yNWLZbeoF8", // chin
                "product_11": "price_1RyGYYIO0M0lx6yN2u3EZ9bN", // chin
                "product_12": "price_1RyGYmIO0M0lx6yN8cTD5B2s", // chin
                "product_13": "price_1RyGZ1IO0M0lx6yNkPtjbGGl", // chin
                "product_14": "price_1RyGZCIO0M0lx6yNsCxzz6Eg", // chin
                "product_15": "price_1RyGZlIO0M0lx6yNLKU3owY4", // chin
                "product_16": "price_1RyGZvIO0M0lx6yNCZlidYfH", // chin
                "product_17": "price_1RyGaFIO0M0lx6yNYn67q07P", // chin
                "product_18": "price_1RyGaUIO0M0lx6yNOKldur2K", // chin
                "product_19": "price_1RyGasIO0M0lx6yNncimM5GY", // chin
                "product_20": "price_1RyGb4IO0M0lx6yNpBoHM4WJ", // chin
                "product_21": "price_1RyGbTIO0M0lx6yNXRQVWnMZ", // chin
                "product_22": "price_1RyGbsIO0M0lx6yNl12eGnXY", // chin
                "product_23": "price_1RyGcCIO0M0lx6yNkL8NqI0m", // chin
                "product_24": "price_1RyGcRIO0M0lx6yNze03prdf", // chin
                "product_25": "price_1RyGckIO0M0lx6yN7A1HNajW", // chin
                "product_26": "price_1RyGd7IO0M0lx6yNBDchKEF9", // chin
                "product_27": "price_1RyGdIIO0M0lx6yNGJDGixwy", // chin
                "product_28": "price_1RyGdYIO0M0lx6yNJ8OmZEdj", // chin
                "product_29": "price_1RyGdmIO0M0lx6yNRhaYzAp4", // chin
                "product_30": "price_1RyGe5IO0M0lx6yNlHZtHTF5", // chin
                "product_31": "price_1RyGgxIO0M0lx6yNqBgzuvRX", // chin
                "product_32": "price_1RyGhBIO0M0lx6yN8FLQFyuW", // chin
                "product_33": "price_1RyGhbIO0M0lx6yNzSjy2Uli", // chin
                "product_34": "price_1RyGhqIO0M0lx6yNUsYxqSeP", // chin
                "product_35": "price_1RyGivIO0M0lx6yNQTNVBSxX", // chin
                "product_36": "price_1RyGjQIO0M0lx6yNgdOx6MqF", // chin
                "product_37": "price_1RyGjiIO0M0lx6yNCqg3Vuxn", // chin
                "product_38": "price_1RyGk1IO0M0lx6yNzG5lAy2c", // chin
                "product_39": "price_1RyGkLIO0M0lx6yN4Lvp5lxY", // chin
                "product_40": "price_1RyGkYIO0M0lx6yNDruW8XZn", // chin
                "product_41": "price_1RyGlHIO0M0lx6yNskKM2VsU", // chin
                "product_42": "price_1RyGlZIO0M0lx6yNxe7u0W7E", // chin
                "product_43": "price_1RyGlmIO0M0lx6yNqx4kKW8s", // chin
                "product_44": "price_1RyGoyIO0M0lx6yN74jOKAcD", // chin
                "product_45": "price_1RyGpFIO0M0lx6yNzIqhcr2x", // chin
                "product_46": "price_1RyGpZIO0M0lx6yNLoKCT3Wg", // chin
                "product_47": "price_1RyGqIIO0M0lx6yNCPoD2Wm4", // chin
                "product_48": "price_1RyGqgIO0M0lx6yNbjib7Uc1", // chin
                "product_49": "price_1RyGrEIO0M0lx6yNOfNX4SB7", // chin
                "product_50": "price_1RyGrYIO0M0lx6yN7Rx5h9zu", // chin
                "product_51": "price_1RyGrsIO0M0lx6yNfHJtY79x", // chin
                "product_52": "price_1RyGsFIO0M0lx6yNe1W0ORlM", // chin
                "product_53": "price_1RyGsgIO0M0lx6yN9D47J4UL", // chin
                "product_54": "price_1RyGt6IO0M0lx6yNAs9DN63o", // chin
                "product_55": "price_1RyGtMIO0M0lx6yNcV4P4I6k", // chin
                "product_56": "price_1RyGtsIO0M0lx6yNVZGhysr5", // chin
                "product_57": "price_1RyGuAIO0M0lx6yNs7HNgxDx", // chin
                "product_58": "price_1RyGuUIO0M0lx6yNRs8F3h6D", // chin
                "product_59": "price_1RyGuvIO0M0lx6yNDYbLWPwv", // chin
                "product_60": "price_1RyGv7IO0M0lx6yNRTfvXKXf", // chin
                "product_61": "price_1RyGvQIO0M0lx6yNFwo1inhU", // chin
                "product_62": "price_1RyGvgIO0M0lx6yNtCQwa9da", // chin
                "product_63": "price_1RyGw8IO0M0lx6yNvbGuEsq7", // chin
                "product_64": "price_1RyGwNIO0M0lx6yNa62JC7Lc", // chin
                "product_65": "price_1RyGwgIO0M0lx6yNhgpHj4Mw", // chin
                "product_66": "price_1RyH0ZIO0M0lx6yNYOmZF2kf", // chin
                "product_67": "price_1RyH6gIO0M0lx6yNJUIYewsr", // chin
                "product_68": "price_1RyH6zIO0M0lx6yN0nvaFDuu", // chin
                "product_69": "price_1RyH7DIO0M0lx6yNmtkO0U1B", // chin
                "product_70": "price_1RyH7qIO0M0lx6yNzRM4qgzG", // chin
                "product_71": "price_1RyH8NIO0M0lx6yNfFZv7Kg5", // chin
                "product_72": "price_1RyH90IO0M0lx6yNfr61RCYj", // chin
                "product_73": "price_1RyHE9IO0M0lx6yNOQdS9yl2", // chin
                "product_74": "price_1RyHEXIO0M0lx6yNTAWDO8IK", // chin
                "product_75": "price_1RyHF4IO0M0lx6yNnMUnkRwi", // chin
                "product_76": "price_1RyHFOIO0M0lx6yNmmdNATy3", // chin
                "product_77": "price_1RyHFuIO0M0lx6yN68TPoC0g", // chin
                "product_78": "price_1RyHGDIO0M0lx6yNv0uOerUD", // chin
                "product_79": "price_1RyHGRIO0M0lx6yNcwMjsaSS", // chin
                "product_80": "price_1RyHGnIO0M0lx6yNeju4DcC7", // chin
                "product_81": "price_1RyHHBIO0M0lx6yNXvFKEym3", // chin
                "product_82": "price_1RyHHRIO0M0lx6yNhfs8y8bW", // chin
                "product_83": "price_1RyHHfIO0M0lx6yNbSzaAH8w", // chin
            };
            */

            try {
                let productIds = req.body.productIds;
                if (!Array.isArray(productIds)) {
                    // If single product sent, wrap it in array
                    productIds = [productIds];
                }

                // Build line_items dynamically
                const lineItems = [];
                for (const id of productIds) {
                    const priceId = productPriceMap[id];
                    if (!priceId) return res.status(400).json({ error: "Invalid product: " + id });
                    lineItems.push({ price: priceId, quantity: 1 });
                }

                // Create Stripe Checkout Session
                const session = await stripe.checkout.sessions.create({
                    payment_method_types: ["card"],
                    line_items: lineItems,
                    mode: "payment",
                    discounts: [{coupon: "e4NuPRxe"}],
                    metadata: {
                        customer_date: date,
                        customer_time: time,
                        customer_email: email,
                        customer_message: message,
                        customer_services: services,
                        customer_type: type,
                        customer_price: price,
                        customer_cancelCode: cancelCode,
                        customer_cancelLink: cancelLink,
                        customer_timeTaken: timeTaken,
                    },
                    success_url: url + "/bookings.html?success=true&session_id={CHECKOUT_SESSION_ID}&product=true",
                    cancel_url: url + "/bookings.html?success=false",
                });

                return res.json({ message: 'continue', url: session.url });
            } catch (err) {
                console.error(err);
                return res.status(500).json({ error: "Server error" });
            }
        }

        payProduct();
    }
});

app.post("/pooja/api/check-code", (req, res) => {
    const code = req.body.code;

    const checkQuery = "select * from codes where coupon_code = ?";
    req.db.query(checkQuery, [code], (err, result) => {
        if(err){
            console.error("Error checking code: " + err);
        }

        if(result.length == 0){
            return res.json({ message: 'failure' });
        } else {
            return res.json({ message: 'success', value: result[0].value });
        }
    });
});

app.post("/pooja/api/check-slots", (req, res) => {
    const date = req.body.date;

    const checkQuery = "select * from bookings where booking_date = ?";
    req.db.query(checkQuery, [date], (err, result) => {
        if(err){
            console.error("Error checking bookings: " + err);
        }

        let timesTaken = "";
        let daysClosed = 0;
        if(result.length > 0){
            result.forEach((row, idx) => {
                if(idx > 0){
                    timesTaken += ",," + row.booking_time.slice(0, 5);
                } else {
                    timesTaken = row.booking_time.slice(0, 5);
                }
                if(row.booking_type == "admin"){
                    daysClosed++;
                }
            }); 
            return res.json({ message: 'success', times: timesTaken, closed: daysClosed, bookings: result });
        } else {
            return res.json({ message: 'success', times: timesTaken, closed: daysClosed, bookings: result });
        }
    });
});

app.post("/pooja/api/admin-access", (req, res) => {
    const code = req.body.code;

    if(code == accessKey){
        req.session.admin = true;
        return res.json({ message: 'Success' });
    } else {
        return res.json({ message: 'Failure' });
    }
});

app.get("/pooja/api/check-admin", (req, res) => {
    if(req.session.admin){
        return res.json({ message: 'Success' });
    } else {
        return res.json({ message: 'Failure' });
    }
});

app.post("/pooja/api/get-bookings", (req, res) => {
    let likeStr;
    let likeStr2 = "09090909090";
    if(req.body.month < 10){
        likeStr = "%" + req.body.year + "-0" + String(req.body.month) + "%";
    } else {
        likeStr = "%" + req.body.year + "-" + String(req.body.month) + "%";
    }
    if(req.body.year2){
        if(req.body.month2 < 10){
            likeStr2 = "%" + req.body.year2 + "-0" + String(req.body.month2) + "%";
        } else {
            likeStr2 = "%" + req.body.year2 + "-" + String(req.body.month2) + "%";
        }
    }

    const getBookingsQuery = "select * from bookings where booking_date like ? or booking_date like ?";
    req.db.query(getBookingsQuery, [likeStr, likeStr2], (err, result) => {
        if(err){
            console.error("Error getting bookings: " + err);
            return res.json({ bookings: [] });
        }

        return res.json({ bookings: result });
    });
});

app.post("/pooja/api/verify-cancel", (req, res) => {
    const code = req.body.code;

    const checkQuery = "select * from bookings where cancel_code = ?";
    req.db.query(checkQuery, [code], (err, result) => {
        if(err){
            console.error("Error getting cancel code: " + err);
        }

        if(result.length == 0){
            return res.json({ message: 'Failure' });
        } else {
            return res.json({ message: 'Success' });
        }
    });
});

app.post("/pooja/api/delete-booking", (req, res, next) => {
    if(!req.body.user){
        return res.json({ message: 'Unauth' });
    }
    next();
}, (req, res) => {
    const code = req.body.code;
    const reason = req.body.reason;

    req.db.query("select * from bookings where cancel_code = ? and booking_type = ?", [code, "user"], (err, result) => {
        if(err){
            console.error("Error selecting bookings: " + err);
        }
        
        const deleteQuery = "delete from bookings where cancel_code = ?";
        req.db.query(deleteQuery, [code], async (err, delResult) => {
            if(err){
                console.error("Error deleting bookings: " + err);
            }


            poojaSendClientDelete(result[0].booking_date, reason);
            poojaSendUserDelete(result[0].email, result[0].booking_date, reason);
            if(result[0].coupon_code && result[0].coupon != "Not entered"){
                req.db.query("select * from codes where coupon_code = ?", [result[0].coupon_code], async (err, result) => {
                    if(err){
                        console.error("Error getting id from codes: " + err);
                    }

                    if(result.length > 0){
                        const session = await stripe.checkout.sessions.retrieve(result[0].session_id);
                        const paymentIntentId = session.payment_intent;
                        if (!paymentIntentId) {
                            console.log("no paymentintendid found for coupon");
                            return res.status(400).json({ message: "No payment intent found for this session." });
                        }
                        await stripe.refunds.create({
                        payment_intent: paymentIntentId,
                        });
                        return res.json({ message: 'Success' });
                    }
                });
            }
            else if(result[0].session_id){
                const session = await stripe.checkout.sessions.retrieve(result[0].session_id);
                const paymentIntentId = session.payment_intent;
                if (!paymentIntentId) {
                    console.log("no paymentintendid found for payment");
                    return res.status(400).json({ message: "No payment intent found for this session." });
                }
                await stripe.refunds.create({
                payment_intent: paymentIntentId,
                });
                return res.json({ message: 'Success' });
            }
            return res.json({ message: 'Success' });
        });
    });
});

app.post("/pooja/api/close-all", poojaRequireAdmin, (req, res) => {
    const date = req.body.date;

    const getEmailsQuery = "select * from bookings where booking_date = ?";
    req.db.query(getEmailsQuery, [date], (err, result) => {
        if(err){
            console.error("Error fetching bookings: " + err);
        }

        if(result.length > 0){
            result.forEach(obj => {
                if(obj.booking_type == "user"){
                    poojaSendApologyEmail(obj.email, date);
                }
            });
        }

        const deleteAllQuery = "delete from bookings where booking_date = ?";
        req.db.query(deleteAllQuery, [date], (err, result) => {
            if(err){
                console.error("Error deleting existing bookings: " + err);
            }

            let values = [];
            let times = [
                "09:30", "09:45",
                "10:00", "10:15", "10:30", "10:45",
                "11:00", "11:15", "11:30", "11:45",
                "12:00", "12:15", "12:30", "12:45",
                "13:00", "13:15", "13:30", "13:45",
                "14:00", "14:15", "14:30", "14:45",
                "15:00", "15:15", "15:30", "15:45",
                "16:00", "16:15", "16:30", "16:45",
                "17:00", "17:15", "17:30", "17:45",
                "18:00"
            ];
            for(let i = 0; i < 35; i++){
                values.push([times[i], date, "marceauowen@gmail.com", "Not entered", "Not entered", "No Services", "admin", "£0", "n/a"]);
            }
            const closeQuery = "insert into bookings (booking_time, booking_date, email, message, coupon_code, services, booking_type, price, cancel_code) values ?";
            req.db.query(closeQuery, [values], (err, result) => {
                if(err){
                    console.error("Error inserting fake bookings: " + err);
                }

                return res.json({ message: 'Success' });
            });
        });    
    });
});

app.post("/pooja/api/show-bookings", poojaRequireAdmin, (req, res) => {
    const date = req.body.date;

    const getBookingsQuery = "select * from bookings where booking_date = ? and booking_type = ?";
    req.db.query(getBookingsQuery, [date, "user"], (err, result) => {
        if(err){
            console.error("Error getting bookings: " + err);
        }

        return res.json({ message: 'Success', arrayObjs: result });
    });
});

app.post("/pooja/api/open-day", poojaRequireAdmin, (req, res) => {
    const date = req.body.date;

    const openQuery = "delete from bookings where booking_date = ?";
    req.db.query(openQuery, [date], (err, result) => {
        if(err){
            console.error("Error opening day: " + err);
        }

        return res.json({ message: 'Success' });
    });
});

app.post("/pooja/api/admin-slots", poojaRequireAdmin, (req, res) => {
    const date = req.body.date;

    const selectAdminSlots = "select * from bookings where booking_date = ? and booking_type = ?";
    req.db.query(selectAdminSlots, [date, "admin"], (err, result) => {
        if(err){
            console.error("Error selecting admin slots: " + err);
        }

        return res.json({ message: 'success', slots: result });
    });
});

app.post("/pooja/api/open-slot", poojaRequireAdmin, (req, res) => {
    const id = req.body.id;

    const openSlotQuery = "delete from bookings where id = ?";
    req.db.query(openSlotQuery, [id], (err, result) => {
        if(err){
            console.error("Error opening slot: " + err);
        }

        return res.json({ message: 'success' });
    });
});

app.post("/pooja/api/remove-slot", poojaRequireAdmin, (req, res) => {
    const date = req.body.date; 
    const time = req.body.time; 

    const values = [time, date, "marceauowen@gmail.com", "Not entered", "Not entered", "No Services", "admin", "£0", "n/a"];
    const closeQuery = "insert into bookings (booking_time, booking_date, email, message, coupon_code, services, booking_type, price, cancel_code) values (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    req.db.query(closeQuery, values, (err, result) => {
        if(err){
            console.error("Error removing slot: " + err);
        }

        return res.json({ message: 'success' });
    });
});

app.get("/pooja/api/verify-booking", poojaRequireAdmin, (req, res) => {
    const changeStatusQuery = "update bookings set payment_status = ? where reference_code = ?";
    req.db.query(changeStatusQuery, ["verified", req.query.verify], (err, result) => {
        if(err){
            console.error("Error changing payment status: " + err);
        }

        return res.json({ message: 'success' });
    });
});

app.get("/pooja/api/verify-gift", poojaRequireAdmin, (req, res) => {
    const getVoucherQuery = "select * from codes where reference_code = ?";
    req.db.query(getVoucherQuery, [req.query.verifyvoucher], (err, result) => {
        if(err){
            console.error("Error getting vouchers: " + err);
            return res.json({ message: 'failure' });
        }

        if(result.length == 1){
            poojaSendUserVoucher(result[0].email, result[0].coupon_code);
            return res.json({ message: 'success' });
        } else {
            return res.json({ message: 'failure' });
        }
    });
});

app.post("/pooja/api/submit-form", (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const phone = req.body.phone;
    const message = req.body.message;

    if(!message){
        message = "Not entered";
    }
    poojaSendClientForm("info@poojasbeautysalon.com", name, email, phone, message);
    return res.json({ message: 'success' });
});


app.post("/pooja/api/create-checkout-session", async (req, res) => {
  try {
    const amount = req.body.amount * 100;

    if(!isValidEmail(req.body.email)){
        return res.json({ message: 'invalid email' });
    }

    // Create a Checkout Session
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "gbp",
            product_data: {
              name: "Voucher Purchase",
            },
            unit_amount: amount, // price in cents
          },
          quantity: 1,
        },
      ],
        mode: "payment", // one-time payment
        customer_email: req.body.email,
        success_url: url + `/bookings.html?success=true&session_id={CHECKOUT_SESSION_ID}&voucherp=true`,
        cancel_url: url + "/bookings.html?success=false",
    });

    res.json({ message: 'success', url: session.url });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: 'falied' });
  }
});

app.get("/pooja/api/verify-session", async (req, res) => {
  const sessionId = req.query.session_id;

  try {
    const session = await stripe.checkout.sessions.retrieve(sessionId);

    if (session.payment_status === "paid") {
      res.json({ paid: true, session });
    } else {
      res.json({ paid: false, session });
    }
  } catch (err) {
    console.error("Error verifying session:", err);
    res.status(500).json({ paid: false, error: err.message });
  }
});

app.post("/pooja/api/create-gift", async (req, res) => {
    const id = req.body.id;
    const session = await stripe.checkout.sessions.retrieve(id);

    if(session.payment_status != "paid"){
        return res.json("failed");
    }

    const amount = session.amount_total / 100;
    const email = session.customer_email;
    
    const newGift = "GIFT" + poojaGenerateNumber();

    req.db.query("select * from codes where session_id = ?", [id], (err, result) => {
        if(err){
            console.error("Error checking if session was used: " + err);
        }

        if(result.length > 0){
            return res.json({ message: 'used' });
        }

        const createGiftQuery = "insert into codes (coupon_code, code_status, value, email, session_id) values (?, ?, ?, ?, ?)";
        req.db.query(createGiftQuery, [newGift, "active", amount, email, id], (err, result) => {
            if(err){
                console.error("Error creating new code: " + err);
                return res.json({ message: 'failed' });
            }

            if(!isValidEmail(email)){
                return res.json({ message: 'inavlid email' });
            }

            poojaSendUserVoucher(email, newGift);
            poojaSendClientGiftRequest(email, amount);
            return res.json({ message: 'success' });
        });
    });
});

app.post("/pooja/api/verify-booking", async (req, res) => {
    const id = req.body.id;
    const session = await stripe.checkout.sessions.retrieve(id);

    if(session.payment_status != "paid"){
        return res.json("failed");
    }

    let timeTaken = session.metadata.customer_timeTaken;
    let values = [];
    let emailFinish;
    for(let i = 0; i < timeTaken; i++){
        let finishTime = null;
        let minNum = Number(session.metadata.customer_time.slice(3, 5));
        let newTime = session.metadata.customer_time.slice(0, 3) + String(minNum + (15 * i));
        if(minNum + (15 * i) > 45){
            let exceed = Math.floor((minNum + (15 * i)) / 60);
            newTime = String(Number(session.metadata.customer_time.slice(0, 2)) + exceed) + ":" + String((minNum + (15 * i)) - (60 * exceed));
            if(String((minNum + (15 * i)) - (60 * exceed)) == "0"){
                newTime = newTime + "0";
            }
        }
        let rowType = "filler";
        if(i == 0){
            rowType = "user";
            newTime = session.metadata.customer_time;

            let lastTime = session.metadata.customer_time.slice(0, 3) + String(minNum + (15 * (timeTaken - 1)));
            if(minNum + (15 * (timeTaken - 1)) > 45){
                let exceed = Math.floor((minNum + (15 * (timeTaken - 1))) / 60);
                lastTime = String(Number(session.metadata.customer_time.slice(0, 2)) + exceed) + ":" + String((minNum + (15 * (timeTaken - 1))) - (60 * exceed));
                if(String((minNum + (15 * i)) - (60 * exceed)) == "0"){
                    lastTime = lastTime + "0";
                }
            }
            finishTime = lastTime.slice(0, 3) + String(Number(lastTime.slice(3)) + 15);
            if((Number(lastTime.slice(3)) + 15) == 60){
                finishTime = String(Number(lastTime.slice(0, 2)) + 1) + ":00";
            }
            emailFinish = finishTime;
        }
        values.push([session.metadata.customer_date, newTime, session.metadata.customer_email, session.metadata.customer_message, null, session.metadata.customer_services, rowType, session.metadata.customer_price, session.metadata.customer_cancelCode, "Paid Online", timeTaken, finishTime, id]);
    }
    
    const insertQuery = "insert into bookings (booking_date, booking_time, email, message, coupon_code, services, booking_type, price, cancel_code, payment_status, time_taken, finish_time, session_id) values ?";
    req.db.query(insertQuery, [values], (err, result) => {
        if(err){
            console.error("Error updating booking: ", err);
            return res.json({ message: 'failed' });
        }

        poojaSendClientEmail(process.env.pooja_ADMIN_EMAIL, session.metadata.customer_date, session.metadata.customer_time + " - " + emailFinish, session.metadata.customer_email, session.metadata.customer_message, session.metadata.customer_services, session.metadata.customer_price);
        poojaSendClientEmail("jackbaileywoods@gmail.com", session.metadata.customer_date, session.metadata.customer_time + " - " + emailFinish, session.metadata.customer_email, session.metadata.customer_message, session.metadata.customer_services, session.metadata.customer_price);
        poojaSendUserEmail(session.metadata.customer_email, session.metadata.customer_date, session.metadata.customer_time + " - " + emailFinish, session.metadata.customer_cancelLink);
        return res.json({ message: 'success' });
    });
});
/*//////////////////////////////////////////////////////////////////////////////////*/




/*//////////////////////////////////// CAD GOLF /////////////////////////////////*/
async function cadgolfSendEmail(userEmail, text) {
    const dataToSend = { reciever: userEmail, text: text, service: 'nextdesign' };
    try {
        const response = await fetch('https://email-sender-lkex.vercel.app/api/send-email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json', 
            },
            body: JSON.stringify(dataToSend), 
        });

        if (!response.ok) {
            const errorData = await response.json();
            console.error('Error:', errorData.error);
            return;
        }
    } catch (error) {
        console.error('Error posting data:', error);
    }
}
function cadgolfSendClientNotification(event, name, players, email){
    cadgolfSendEmail(process.env.cadgolf_ADMIN_EMAIL, `<p>Hi, a new booking was made from your website by ${name}.<br><br>Event: ${event}<br><br>Players: ${players.replace(/,,/g, ", ")}<br><br> Email: ${email}`);
    cadgolfSendEmail("jackbaileywoods@gmail.com", `<p>Hi, a new booking was made from your website by ${name}.<br><br>Event: ${event}<br><br>Players: ${players.replace(/,,/g, ", ")}<br><br> Email: ${email}`);
}
function isValidEmail(email){
	const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
	return emailRegex.test(email);
}


app.post("/cadgolf/api/submit", (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const phone = req.body.phone;
    const team = req.body.player1 + ",," + req.body.player2 + ",," + req.body.player3;
    const event = JSON.parse(req.body.event);
    const getEventQuery = "select * from all_events where id = ?";
    req.db.query(getEventQuery, [event.id], (err, result) => {
        if(err){
            console.error("Error getting event: " + err);
        }

        if(result.length > 0){
            if(event.current_slots + Number(event.team_size) > event.max_slots){
                return res.json({ message: 'Limit Exceeded' });
            }
            const insertQuery = "insert into bookings (event_id, booking_name, email, phone, team) values (?, ?, ?, ?, ?);";
            req.db.query(insertQuery, [event.id, name, email, phone, team], (err, result) => {
                if(err){
                    console.error("Error inserting booking: " + err);
                    return res.json({ message: 'Failure in DB' });
                }

                const updateSlotsQuery = "update all_events set current_slots = ? where id = ?";
                req.db.query(updateSlotsQuery, [event.current_slots + Number(event.team_size), event.id], (err, result) => {
                    if(err){
                        console.error("Error updating slots: " + err);
                        return res.json({ message: 'Failure in DB (slots)' });
                    }


                    cadgolfSendClientNotification(event.title, name, team, email);
                    return res.json({ message: "Success" });
                });
            });
        } else {
            return res.json({ message: 'Failure' });
        }
    });
});

app.post("/cadgolf/get-events", (req, res) => {
    let likeStr;
    if(req.body.month < 10){
        likeStr = "%" + req.body.year + "-0" + String(req.body.month) + "%";
    } else {
        likeStr = "%" + req.body.year + "-" + String(req.body.month) + "%";
    }

    const getBookingsQuery = "select * from all_events where event_date like ?";
    req.db.query(getBookingsQuery, [likeStr], (err, result) => {
        if(err){
            console.error("Error getting bookings: " + err);
            return res.json({ bookings: [] });
        }

        return res.json({ bookings: result });
    });
});
/*////////////////////////////////////////////////////////////////////////////*/




/*//////////////////////////////////// NEXT DESIGN /////////////////////////////////*/
async function nextSendEmail(userEmail, text) {
    const dataToSend = { reciever: userEmail, text: text, service: 'nextdesign' };
    try {
        const response = await fetch('https://email-sender-lkex.vercel.app/api/send-email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json', 
            },
            body: JSON.stringify(dataToSend), 
        });

        if (!response.ok) {
            const errorData = await response.json();
            console.error('Error:', errorData.error);
            return;
        }
    } catch (error) {
        console.error('Error posting data:', error);
    }
}
function nextSendClientEmail(userEmail, date, time, email, message){
    nextSendEmail(userEmail, `<p>Hello, a call was booked with NextDesign for: ${date}, ${time}\n\nEmail: ${email}\n\nMessage: ${message}</p>`);
}
function nextSendClientDelete(userEmail, date, time){
    nextSendEmail(userEmail, `<p>Hello, a booking was cancelled with NextDesign for: ${date}, ${time}.</p>`);
}
function nextSendUserEmail(userEmail, date, time, link) {  
    nextSendEmail(userEmail, `<p>Hello, you booked a call with NextDesign for ${date}, ${time}\n\nCancel anytime with this link: ${link}</p>`);
}
function nextSendUserDelete(userEmail) {
    nextSendEmail(userEmail, `<p>Hello, your booking for NextDesign has been cancelled. Please rebook at your convenience.</p>`);
}
function isValidEmail(email){
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}
function nextGenerateNumber(){
    return crypto.randomBytes(5).toString('hex'); 
}
function nextRequireAdmin(req, res, next){
    const code = req.query.code;
    if(code != process.env.next_ADMIN_CODE) {
        console.log("admin fail");
        return res.json({ message: 'failure' });
    }
    next();
}


app.post("/nextdesign/api/book-appointment", (req, res) => {
    const date = req.body.date;
    const time = req.body.time;
    const email = req.body.email;
    const phone = req.body.phone;
    const message = req.body.message;
    const type = req.body.type;

    if(!isValidEmail(email)){
        return res.json({ message: 'Failure' });
    }

    const cancelCode = nextGenerateNumber();
    const cancelLink = url + "/?cancel=" + cancelCode;

    const insertQuery = "insert into bookings (booking_date, booking_time, email, phone_number, message, booking_type, cancel_code) values (?, ?, ?, ?, ?, ?, ?)";
    req.db.query(insertQuery, [date, time.replace(/ /g, ""), email, phone, message, type, cancelCode], (err, result) => {
        if(err){
            console.error("Error updating booking: ", err);
            return res.json({ message: 'Failure' });
        }

        nextSendClientEmail(process.env.next_ADMIN_EMAIL, date, time, email, message);
        nextSendUserEmail(email, date, time, cancelLink);
        return res.json({ message: 'success' });
    });
});

app.post("/nextdesign/api/get-bookings", (req, res) => {
    let likeStr;
    if(req.body.month < 10){
        likeStr = "%" + req.body.year + "-0" + String(req.body.month) + "%";
    } else {
        likeStr = "%" + req.body.year + "-" + String(req.body.month) + "%";
    }


    const getBookingsQuery = "select * from bookings where booking_date like ?";
    req.db.query(getBookingsQuery, [likeStr], (err, result) => {
        if(err){
            console.error("Error getting bookings: " + err);
            return res.json({ bookings: [] });
        }

        return res.json({ bookings: result });
    });
});

app.post("/nextdesign/api/extra-slots", (req, res) => {
    const date = req.body.date;

    const getExtraSlots = "select * from extra_slots where booking_date = ?";
    req.db.query(getExtraSlots, [date], (err, result) => {
        if(err){
            console.error("Error getting extra slots: " + err);
        }

        return res.json({ slots: result });
    });
});

app.post("/nextdesign/api/check-slots", (req, res) => {
    const date = req.body.date;

    const checkQuery = "select * from bookings where booking_date = ?";
    req.db.query(checkQuery, [date], (err, result) => {
        if(err){
            console.error("Error checking bookings: " + err);
        }

        let timesTaken = "";
        if(result.length > 0){
            result.forEach((row, idx) => {
                if(idx > 0){
                    timesTaken += ",," + row.booking_time.slice(0, 5);
                } else {
                    timesTaken = row.booking_time.slice(0, 5);
                }
            }); 
            return res.json({ message: 'success', times: timesTaken });
        } else {
            return res.json({ message: 'success', times: timesTaken});
        }
    });
});

app.get("/nextdesign/api/admin-code", nextRequireAdmin, (req, res) => {
    return res.json({ message: 'success' });
});

app.post("/nextdesign/api/close-all", nextRequireAdmin, (req, res) => {
    const date = req.body.date;
    const times = req.body.times;

    const getEmailsQuery = "select * from bookings where booking_date = ?";
    req.db.query(getEmailsQuery, [date], (err, result) => {
        if(err){
            console.error("Error fetching bookings: " + err);
        }

        if(result.length > 0){
            let allStr = "";
            result.forEach(obj => {
                if(!allStr.includes(obj.email)){
                    allStr += obj.email;
                    nextSendUserDelete(obj.email);
                }
            });
        }

        const deleteAllQuery = "delete from bookings where booking_date = ?";
        req.db.query(deleteAllQuery, [date], (err, result) => {
            if(err){
                console.error("Error deleting existing bookings: " + err);
            }

            let values = [];
            let times = [
                "07:00", "07:30",
                "08:00", "08:30",
                "09:00", "09:30",
                "10:00", "10:30",
                "11:00", "11:30",
                "12:00", "12:30",
                "13:00", "13:30",
                "14:00", "14:30",
                "15:00", "15:30",
                "16:00", "16:30",
                "17:00", "17:30",
                "18:00", "18:30",
                "19:00", "19:30",
                "20:00", "20:30",
                "21:00", "21:30",
                "22:00", "22:30",
                "23:00", "23:30"
            ];
            for(let i = 0; i < 34; i++){
                values.push([times[i].replace(/ /g, ""), date, "marceauowen@gmail.com", "Not entered", "admin", "n/a"]);
            }
            const closeQuery = "insert into bookings (booking_time, booking_date, email, message, booking_type, cancel_code) values ?";
            req.db.query(closeQuery, [values], (err, result) => {
                if(err){
                    console.error("Error inserting fake bookings: " + err);
                }

                return res.json({ message: 'success' });
            });
        });    
    });
});

app.post("/nextdesign/api/open-day", nextRequireAdmin, (req, res) => {
    const date = req.body.date;

    const openQuery = "delete from bookings where booking_date = ?";
    req.db.query(openQuery, [date], (err, result) => {
        if(err){
            console.error("Error opening day: " + err);
        }

        return res.json({ message: 'success' });
    });
});

app.post("/nextdesign/api/show-bookings", nextRequireAdmin, (req, res) => {
    const date = req.body.date;

    const getBookingsQuery = "select * from bookings where booking_date = ? and booking_type = ?";
    req.db.query(getBookingsQuery, [date, "user"], (err, result) => {
        if(err){
            console.error("Error getting bookings: " + err);
        }

        return res.json({ message: 'success', arrayObjs: result });
    });
});

app.post("/nextdesign/api/verify-cancel", (req, res) => {
    const code = req.body.code;

    const checkQuery = "select * from bookings where cancel_code = ?";
    req.db.query(checkQuery, [code], (err, result) => {
        if(err){
            console.error("Error getting cancel code: " + err);
        }

        if(result.length == 0){
            return res.json({ message: 'Failure' });
        } else {
            return res.json({ message: 'Success' });
        }
    });
});

app.post("/nextdesign/api/delete-booking", (req, res) => {
    const code = req.body.code;

    const deleteQuery = "delete from bookings where cancel_code = ?";
    req.db.query(deleteQuery, [code], (err, result) => {
        if(err){
            console.error("Error deleting bookings: " + err);
        }

        req.db.query("select * from bookings where cancel_code = ?", [code], (err, result) => {
            if(err){
                console.error("Error selecting *: " + err);
            }

            if(result.length == 1){
                nextSendUserDelete(result[0].email);
                nextSendClientDelete(process.env.next_ADMIN_EMAIL, result[0].booking_date, result[0].booking_time);
            }
            return res.json({ message: 'success' });
        });
    });
});

app.post("/nextdesign/api/remove-slot", nextRequireAdmin, (req, res) => {
    const date = req.body.date; 
    const time = req.body.time; 

    const values = [time, date, "marceauowen@gmail.com", "Not entered", "admin", "n/a"];
    const closeQuery = "insert into bookings (booking_time, booking_date, email, message, booking_type, cancel_code) values (?, ?, ?, ?, ?, ?)";
    req.db.query(closeQuery, values, (err, result) => {
        if(err){
            console.error("Error removing slot: " + err);
            return res.json({ message: 'failure' });
        }

        return res.json({ message: 'success' });
    });
});

app.post("/nextdesign/api/open-slot", nextRequireAdmin, (req, res) => {
    const id = req.body.id;

    const openSlotQuery = "delete from bookings where id = ?";
    req.db.query(openSlotQuery, [id], (err, result) => {
        if(err){
            console.error("Error opening slot: " + err);
        }

        return res.json({ message: 'success' });
    });
});

app.post("/nextdesign/api/create-slot", nextRequireAdmin, (req, res) => {
    const date = req.body.date;
    const time = req.body.time;

    const insertQuery = "insert into extra_slots (booking_date, booking_time) values (?, ?)";
    req.db.query(insertQuery, [date, time], (err, result) => {
        if(err){
            console.error("Error inserting extra slot: " + err);
            return res.json({ message: 'failure' });
        }

        return res.json({ message: 'success' });
    });
});
/*//////////////////////////////////////////////////////////////////////////////////*/





app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});