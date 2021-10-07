//process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';       //allows to get files from https even if certificate invalid
var fileUpload = require('express-fileupload')          //yarn add express-fileupload
var compression = require('compression')                //yarn add compression
var express = require('express');                       //yarn add express -- save
var sql = require('mssql');                             //yarn add mssql -- save
var jwt = require("jsonwebtoken");                      //yarn add jsonwebtoken --save
var request = require('request');                       //yarn add request --save
var httpntlm = require('httpntlm');                 //yarn add httpntlm
var axios = require('axios');                         //yarn add axios --save
//const RequestIp = require('@supercharge/request-ip')    //yarn add @supercharge/request-ip  
var requestIp = require('request-ip');                  //yarn add request-ip
var soapRequest = require('easy-soap-request'); //yarn add easy-soap-request
//var curl = require('curl');                           //yarn add curl --save
//var superagent = require('superagent');               //yarn add superagent --save
//var WebSocket  = require("ws");                         //yarn add ws --save
var nodemailer = require("nodemailer");                 //yarn add nodemailer --save
var emlFormat = require("eml-format");                //yarn add eml-format --save
//var socketIO = require("socket.io");                  //yarn add socket.io --save
var ExcelJS = require('exceljs');             //yarn add exceljs --save
//var url = require('url');
//var http = require('http');
var https = require('https');
var app = express();
var fs = require('fs');
var bodyParser = require('body-parser');
var logToFile = function(message){ fs.appendFile(process.env.logPathFile, new Date().toISOString() + '\t' + message + '\r\n', (err) => { if (err) throw err; } ); }


logToFile('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
logToFile('API starting2...')
logToFile('Express Version: ' + require('express/package').version)
logToFile('Node Version: ' + process.version)
logToFile('Process ID: ' + process.pid)
logToFile('Running Path: ' + process.cwd())
logToFile('New Comment')

//#region Public_Functions_&_Variables
app.use(compression())  //Enable Compression
app.use(fileUpload());  //Enable File Upload
app.use(bodyParser.json({limit: '50mb'}));  //Use bodyParser, and set file size
app.use(bodyParser.urlencoded({limit: '50mb', extended: true})); //Use bodyParser, and set file size
app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");//Enabling CORS 
    res.header("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST,PUT");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, contentType, Content-Type, Accept, Authorization");
    next();
});

var connectionPool = new sql.ConnectionPool(JSON.parse(process.env.dbConfig), (err, pool) => {
    if(err){
        logToFile('Error creating SQL connectionPool:' + err)
    }else{
        logToFile('SQL ConnectionPool Created with database: ' + pool.config.database)
    }
})

var veryfyToken = function(req, res, next){
    const bearerHeader = req.headers['authorization'];//get auth header value
    if(typeof bearerHeader !== 'undefined'){
        const bearer = bearerHeader.split(' '); //split by space
        const bearerToken = bearer[1]; //get token from array
        jwt.verify(bearerToken, process.env.secretEncryptionJWT, (jwtError, authData) => {
            if(jwtError){
                logToFile('Se produjo un error en la validación del token')
                logToFile(jwtError)
                res.status(403).send(jwtError);
            }else{
                if(req.body.sys_user_code || req.body.sys_user_code){
                    if( (authData.user.sys_user_code == req.query.sys_user_code) || (authData.user.sys_user_code == req.body.sys_user_code)    ){
                        req.token = bearerToken; //set the token
                        next();
                    }else{
                        logToFile('No coincide el código del usuario con el token')
                        logToFile(authData.user.sys_user_code)
                        logToFile(req.query.sys_user_code)
                        logToFile(req.body.sys_user_code)
                        res.status(403).send({message: 'No coincide el código del usuario con el token'});
                        return;
                    }
                }else{
                    req.token = bearerToken; //set the token
                    next();
                }
            }
        })
    }else{
        logToFile('No se pudo verificar token')
        res.status(403).send({message: 'No se pudo verificar token'});
    }
}

app.get(process.env.iisVirtualPath+'status', function (req, res) {
    //res.send(JSON.stringify(connectionPool));
    let respuesta = {
         status: 'UP'
        ,uptime: process.uptime()
        ,nodeVersion: process.version
        ,pid: process.pid
        ,platform: process.platform
        ,runningPath: process.cwd()
        ,memoryUsage: process.memoryUsage()
        ,resourceUsage: process.resourceUsage()
        ,connectionPool_eventsCount: connectionPool._eventsCount
        ,connectionPool_db: connectionPool.config.database
        ,connectionPool_connected: connectionPool._connected
        //,connectionPool_poolMax: connectionPool.pool.max
        //,connectionPool_poolUsed: connectionPool.pool.used
        
    }
    res.send(JSON.stringify(respuesta));
    //res.send(JSON.stringify(connectionPool));
});
app.get(process.env.iisVirtualPath+'getIPaddress', function (req, res) {    
    /*var idAddressB = req.header('x-forwarded-for') || req.connection.remoteAddress;
    logToFile('idAddressB');
    logToFile(idAddressB);*/
    var idAddress = requestIp.getClientIp(req);
    res.status(200).send(idAddress);
})
//#endregion Public_Functions_&_Variables


//#region Version_1_0_0

//#region SESSION_OTHERS
app.post(process.env.iisVirtualPath+'spSysLogin', function (req, res) {
    let start = new Date()
    logToFile('!!! New Login attempt from ' + 'Usuario: ' + req.body.sys_user_id + ' (' + req.ip + ')')
    new sql.Request(connectionPool)
    .input('sys_user_id', sql.VarChar(250), req.body.sys_user_id )
    .input('sys_user_password', sql.VarChar(100), req.body.sys_user_password )
    .execute('spSysLogin', (err, result) => {
        logToFile("Request:  " + req.originalUrl)
        //NO quiero grabar la clave logToFile("Request:  " + JSON.stringify(req.body))
        logToFile("Perf spSysLogin:  " + ((new Date() - start) / 1000) + ' secs' )
        if(err){
            if(err&&err.originalError&&err.originalError.info){
                logToFile('DB Error: ' + JSON.stringify(err.originalError.info))
            }else{
                logToFile('DB Error: ' + JSON.stringify(err.originalError))
            }
            res.status(400).send(err.originalError);
            return;
        }
        if(result.recordset.length > 0){
            const user = {
                 username: req.body.sys_user_id
                ,sys_user_code: result.recordset[0].sys_user_code
                ,sys_profile_id: result.recordset[0].sys_profile_id
            }
            jwt.sign({user: user}, process.env.secretEncryptionJWT, (err, token) => {
                if(err){
                    logToFile('JWT Error: ' + err)
                    res.status(400).send(err);
                    return;
                }else{
                    new sql.Request(connectionPool)
                    .input('sys_user_code', sql.Int, result.recordset[0].sys_user_code)
                    .input('token', sql.NVarChar(sql.MAX), token)
                    .input('device_data', sql.NVarChar(sql.MAX), null)//se puede agregar información adicional
                    .execute('spSysLoginLogToken', (errA, resultA) => {
                        if(errA){
                            if(errA&&errA.originalError&&errA.originalError.info){
                                logToFile('DB Error: ' + JSON.stringify(errA.originalError.info))
                            }else{
                                logToFile('DB Error: ' + JSON.stringify(errA.originalError))
                            }
                            res.status(400).send(errA.originalError);
                            return;
                        }
                        
                        logToFile('Welcome: ' + req.body.sys_user_id)
                        userToken = token
                        result.recordset[0].jwtToken = token
                        res.setHeader('content-type', 'application/json');
                        res.status(200).send(result.recordset);
                    })
                }
            })
        }else{
            res.status(400).send('Error de Inicio de Sesión');
            return;
        }
    })

});
app.post(process.env.iisVirtualPath+'sp_sys_users_reset', function (req, res) {
    let start = new Date()
    logToFile('!!! New password Reset attempt for ' + req.body.sys_user_id)
    new sql.Request(connectionPool)
    .input('sys_user_id', sql.VarChar(250), req.body.sys_user_id )
    .input('source_data', sql.VarChar(100), req.ip )
    .input('url_destination', sql.VarChar(250), req.body.url_destination )
    .execute('sp_sys_users_reset', (err, result) => {
        logToFile("Request:  " + req.originalUrl)
        //NO quiero grabar la clave logToFile("Request:  " + JSON.stringify(req.body))
        logToFile("Perf spSysLogin:  " + ((new Date() - start) / 1000) + ' secs' )
        if(err){
            if(err&&err.originalError&&err.originalError.info){
                logToFile('DB Error: ' + JSON.stringify(err.originalError.info))
            }else{
                logToFile('DB Error: ' + JSON.stringify(err.originalError))
            }
            res.status(400).send(err.originalError);
            return;
        }
        
        if(result.recordset.length > 0){
            try{
                logToFile("Temp Sent: " + JSON.stringify(result.recordset) )
                let transporter = nodemailer.createTransport({
                    host: process.env.notifyMailHost,
                    port: process.env.notifyMailPort,
                    secure: process.env.notifyMailSecure,
                    auth: {
                      user: process.env.notifyMailUser,
                      pass: process.env.notifyMailPass,
                    },
                    tls: {
                        rejectUnauthorized: false// do not fail on invalid certs
                    },
                });

                var mailOptions = {
                    from: '"BITT" <'+process.env.notifyMailUser+'>', //from debe contener entre <> la misma cuenta que se usa en el Transporter (podría sacarla de [auth.user] )
                    //to: req.body.destinations,
                    to: result.recordset[0].destination_address,
                    subject: 'Solicitud de Código Temporal',
                    text: result.recordset[0].destination_message_HTML,
                    html: result.recordset[0].destination_message_HTML
                };

                logToFile("Sending Mail...")
                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        logToFile("Error sending mail")
                        logToFile(error)
                        res.status(400).send(error);
                        return;
                    }
                    
                    logToFile("Message Sent: " + JSON.stringify(info) )
                    logToFile("Perf sp_sys_users_reset:  " + ((new Date() - start) / 1000) + ' secs')
                    res.status(200).send(info);
                });
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }else{
            res.status(400).send('Error de Inicio de Sesión');
            return;
        }
    })

});
app.post(process.env.iisVirtualPath+'sp_sys_users_reset_validate', function (req, res) {
    let start = new Date()
    logToFile('!!! New password Reset attempt ' + req.ip )
    new sql.Request(connectionPool)
    .input('sys_user_id', sql.VarChar(250), req.body.sys_user_id )
    .input('sys_user_password', sql.VarChar(100), req.body.sys_user_password )
    .execute('spSysLogin', (err, result) => {
        logToFile("Request:  " + req.originalUrl)
        //NO quiero grabar la clave logToFile("Request:  " + JSON.stringify(req.body))
        logToFile("Perf spSysLogin:  " + ((new Date() - start) / 1000) + ' secs' )
        if(err){
            if(err&&err.originalError&&err.originalError.info){
                logToFile('DB Error: ' + JSON.stringify(err.originalError.info))
            }else{
                logToFile('DB Error: ' + JSON.stringify(err.originalError))
            }
            res.status(400).send(err.originalError);
            return;
        }
        if(result.recordset.length > 0){
            const user = {
                 username: req.body.sys_user_id
                ,sys_user_code: result.recordset[0].sys_user_code
                ,sys_profile_id: result.recordset[0].sys_profile_id
            }
            jwt.sign({user: user}, process.env.secretEncryptionJWT, (err, token) => {
                if(err){
                    logToFile('JWT Error: ' + err)
                    res.status(400).send(err);
                    return;
                }else{
                    logToFile('Welcome: ' + req.body.sys_user_id)
                    userToken = token
                    result.recordset[0].jwtToken = token
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                }
            })
        }else{
            res.status(400).send('Error de Inicio de Sesión');
            return;
        }
    })

});
app.get(process.env.iisVirtualPath+'spSysUserMainData', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('sys_profile_id', sql.Int, req.query.sys_profile_id )
            .input('sys_user_language', sql.VarChar(25), req.query.sys_user_language )
            .input('sys_user_code', sql.Int, req.query.sys_user_code )
            .execute('spSysUserMainData', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysUserMainData:  " + ((new Date() - start) / 1000) + ' secs')
                if(err){
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.get(process.env.iisVirtualPath+'spSysUserMainDataMobile', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('sys_profile_id', sql.Int, req.query.sys_profile_id )
            .input('sys_user_language', sql.VarChar(25), req.query.sys_user_language )
            .input('sys_user_code', sql.Int, req.query.sys_user_code )
            .execute('spSysUserMainDataMobile', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysUserMainDataMobile:  " + ((new Date() - start) / 1000) + ' secs')
                if(err){
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.get(process.env.iisVirtualPath+'spMyUnreadNotifications', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .execute('spMyUnreadNotifications', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMyUnreadNotifications:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.get(process.env.iisVirtualPath+'spMyNotificationsContacts', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .execute('spMyNotificationsContacts', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMyNotificationsContacts:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.get(process.env.iisVirtualPath+'spMyNotificationsContactMessages', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('contactUserCode', sql.Int, req.query.contactUserCode )
            .execute('spMyNotificationsContactMessages', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMyNotificationsContactMessages:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'uploadFile', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                //logToFile('flag00')
                /*if (!req.files){
                    logToFile('Error en uploadFile (no se recibió archivo)')
                    res.status(400).send('Error en uploadFile (no se recibió archivo)');
                    return;
                }*/
                var fileName = Object.keys(req.files)[0]
                //logToFile('flag01')
                let sampleFile = req.files[fileName]
                //logToFile('flag02')
                logToFile('Upload ' + process.env.filesPath + req.query.upload_file_name)
                sampleFile.mv(process.env.filesPath + req.query.upload_file_name, function(err) {
                    if(err){
                        logToFile('Error escribiendo archivo (uploadFile): ' + JSON.stringify(err))
                        res.status(400).send(err);
                        return;
                    }
                    new sql.Request(connectionPool)
                    .input('attach_id', sql.VarChar(500), req.query.attach_id )
                    .execute('sp_attachs_uploaded', (err, result) => {
                        logToFile("Request:  " + req.originalUrl)
                        logToFile("Perf sp_attachs_uploaded:  " + ((new Date() - start) / 1000) + ' secs' )

                        if(err){
                            logToFile("DB Error:  " + err.procName)
                            logToFile("Error:  " + JSON.stringify(err.originalError.info))
                            res.status(400).send(err.originalError);
                            return;
                        }
                        res.setHeader('content-type', 'application/json');
                        res.status(200).send(result.recordset);
                    })

                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.get(process.env.iisVirtualPath+'downloadFile', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            logToFile("Request:  " + req.originalUrl)
            logToFile("Perf downloadFile:  " + ((new Date() - start) / 1000) + ' secs' )
            res.download((process.env.filesPath + "//" + req.query.fileName))
        }
    })
})
app.get(process.env.iisVirtualPath+'downloadTempFile', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            logToFile("Request:  " + req.originalUrl)
            logToFile("Perf downloadFile:  " + ((new Date() - start) / 1000) + ' secs' )
            res.download((process.env.tempFilesPath + "//" + req.query.fileName), function (err) {
                if (err) {
                    logToFile("Error downloading File...")
                } else {
                    logToFile("Deleting File: " + process.env.tempFilesPath + req.query.fileName);
                    fs.unlink(process.env.tempFilesPath + req.query.fileName, (err) => {
                        if (err) {
                            logToFile("Deleting File error: " + process.env.tempFilesPath + req.query.fileName);
                        }
                    });
                    logToFile("Temp file deleted")
                }
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spAttachGenerateID', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('original_file_name', sql.VarChar(500), req.body.original_file_name )
                .input('file_type', sql.NVarChar(sql.MAX), req.body.file_type )
                .input('file_size', sql.VarChar(sql.Int), req.body.file_size )
                //.input('row_id', sql.Int, req.body.row_id )
                .input('moduleName', sql.VarChar(500), req.body.moduleName )
                .execute('spAttachGenerateID', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spAttachGenerateID:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'saveGridUserState', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('moduleName', sql.VarChar(500), req.body.moduleName )
                .input('gridName', sql.VarChar(500), req.body.gridName )
                .input('gridState', sql.NVarChar(sql.MAX), req.body.gridState )
                .execute('saveGridUserState', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf saveGridUserState:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.get(process.env.iisVirtualPath+'spGetMailFormData', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            //Generates PDF if exists URL
            if(req.query.moduleReportURL){
                logToFile("Generate PDF:  " + req.originalUrl)
                logToFile("Generate PDF as :  " + req.query.uid)
                
                //Config Request
                const agent = new https.Agent({ rejectUnauthorized: false });
                const options = {
                    url: req.query.moduleReportURL //url: 'https://localhost/ReportServer?/mktPO_1&rs:format=PDF&sys_user_code=1&sys_user_language=es&sys_user_company=1&row_id=5'
                    ,followRedirect: true
                    ,followAllRedirects: true
                    ,jar: true
                    ,agent: agent
                    ,strictSSL: false
                };
                request(options).on('error', function(err) {
                    logToFile("Error:  " + JSON.stringify(err))
                    res.status(400).send(err);
                    return;
                }).pipe(fs.createWriteStream((process.env.tempFilesPath + req.query.uid + '.pdf')))
            }
            
              
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(25), req.query.userLanguage )
            .input('moduleName', sql.VarChar(500), req.query.moduleName )
            .input('row_id', sql.Int, req.query.row_id )
            .execute('spGetMailFormData', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spGetMailFormData:  " + ((new Date() - start) / 1000) + ' secs')
                if(err){
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                //Push Attachment to Result (Using Public Internet Path to Temp Files)
                if(req.query.moduleReportURL){
                    let attachments = [{
                         fileName: req.query.moduleName+'_'+req.query.row_id+'.pdf'
                        ,uploadFilename: req.query.uid + '.pdf'
                    }]
                    result.recordset[0].attachments = attachments
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'sendUserMail', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                let transporter = nodemailer.createTransport({
                    host: process.env.notifyMailHost,
                    port: process.env.notifyMailPort,
                    secure: process.env.notifyMailSecure,
                    auth: {
                      user: process.env.notifyMailUser,
                      pass: process.env.notifyMailPass,
                    },
                    tls: {
                        rejectUnauthorized: false// do not fail on invalid certs
                    },
                });
                //convert Attachments
                let attachments = []
                if(req.body.attachments){
                    JSON.parse(req.body.attachments).map(x=>
                        attachments.push({
                             filename: x.fileName
                            ,path: process.env.tempFilesPath + x.uploadFilename
                        })
                    )
                }
                var mailOptions = {
                    from: '"'+req.body.senderName+'" <'+process.env.notifyMailUser+'>', //from debe contener entre <> la misma cuenta que se usa en el Transporter (podría sacarla de [auth.user] )
                    replyTo: req.body.senderMail,
                    to: req.body.destinations,
                    subject: req.body.subjectText,
                    text: req.body.bodyText,
                    html: req.body.bodyText,
                    attachments: attachments
                };

                logToFile("Sending Mail...")
                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        logToFile("Error sending mail")
                        logToFile(error)
                        res.status(400).send(error);
                        return;
                    }
                    //logToFile("Message Message: " + info.messageId)
                    
                    logToFile("Message Sent: " + JSON.stringify(info) )
                    if(req.body.attachments){
                        JSON.parse(req.body.attachments).map(x=>{
                            logToFile("Deleting File: " + process.env.tempFilesPath + x.uploadFilename);
                            fs.unlink(process.env.tempFilesPath + x.uploadFilename, (err) => {
                                if (err) {
                                    logToFile("Deleting File error: " + process.env.tempFilesPath + x.uploadFilename);
                                }
                            });
                        })
                    }
                    logToFile("Perf spGetMailFormData:  " + ((new Date() - start) / 1000) + ' secs')
                    res.status(200).send(info);
                });
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'generateEMLMail', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                let attachments = []
                if(req.body.attachments){
                    JSON.parse(req.body.attachments).map(x=>
                        attachments.push({
                             name: x.fileName
                            ,data: fs.readFileSync(process.env.tempFilesPath + x.uploadFilename),
                            //,path: process.env.tempFilesPath + x.uploadFilename
                        })
                    )
                }
                let destinations = [];
                if(req.body.destinations&&req.body.destinations){
                    req.body.destinations.replace(';',',')
                    req.body.destinations.split(',').map(x=>{
                        destinations.push({
                            //name: '"'+x+'"', 
                            email: x
                        });
                    });
                }
                if(destinations.length<=0){
                    destinations = [{name: req.body.senderMail, email: req.body.senderMail}]
                }
                var data = {
                    from: req.body.senderMail,
                    headers: { "X-Unsent": "1"},
                    to: destinations,
                    subject: req.body.subjectText,
                    html: req.body.bodyText,
                    attachments: attachments
                };
                logToFile("Generating EML: " + process.env.tempFilesPath + req.body.uid + '.eml');
                emlFormat.build(data, function(error, eml) {
                    if(error){
                        logToFile("Generating EML Error")
                        logToFile(error)
                        res.status(400).send(error);
                        return;
                    }
                    fs.writeFileSync(process.env.tempFilesPath + req.body.uid + '.eml', eml);
                    logToFile("EML File created: " + process.env.tempFilesPath + req.body.uid + '.eml')
                    let resultado = {
                        fileName: 'Mail.eml',
                        uploadFilename: req.body.uid + '.eml'
                    }
                    res.status(200).send(resultado);
                });
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//2021 version 4.6.2
app.post(process.env.iisVirtualPath+'generatePDFandEML', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                //Create PDF file based on parameters
                const agent = new https.Agent({ rejectUnauthorized: false });
                const options = {
                    url: req.body.mailReportURL //url: 'https://localhost/ReportServer?/mktPO_1&rs:format=PDF&sys_user_code=1&sys_user_language=es&sys_user_company=1&row_id=5'
                    ,followRedirect: true
                    ,followAllRedirects: true
                    ,jar: true
                    ,agent: agent
                    ,strictSSL: false
                };
                var stream = request(options).on('error', function(err) {
                    logToFile("Error:  " + JSON.stringify(err))
                    res.status(400).send(err);
                    return;
                }).pipe(fs.createWriteStream((process.env.tempFilesPath + req.body.uid + '.pdf')))

                //create attachments variable AFTER file is created (stream finished)
                stream.on('finish', function (){
                    let attachments = []
                    let fileData = null;
                    fileData = fs.readFileSync(process.env.tempFilesPath + req.body.uid + '.pdf');
                    attachments.push({
                        name: req.body.rptName + '.pdf'
                        ,data: fileData,
                        //,path: process.env.tempFilesPath + x.uploadFilename
                    })
                    //fix data for EML generation
                    let destinations = []
                    req.body.destinations.map(x=>{
                        destinations.push({
                            //name: x.contactName,
                            email: x.mail
                        })
                    })
                    if(destinations.length<=0){
                        destinations = [{name: req.body.senderMail, email: req.body.senderMail}]
                    }
                    var data = {
                        from: req.body.senderMail,
                        headers: { "X-Unsent": "1"},
                        to: destinations,
                        subject: req.body.subjectText,
                        html: req.body.bodyText,
                        attachments: attachments
                    };
                    //Generate EML
                    logToFile("Generating EML: " + process.env.tempFilesPath + req.body.uid + '.eml');
                    emlFormat.build(data, function(error, eml) {
                        if(error){
                            logToFile("Generating EML Error")
                            logToFile(error)
                            res.status(400).send(error);
                            return;
                        }
                        fs.writeFileSync(process.env.tempFilesPath + req.body.uid + '.eml', eml);
                        logToFile("EML File created: " + process.env.tempFilesPath + req.body.uid + '.eml')
                        let resultado = {
                            fileName: 'Mail.eml',
                            uploadFilename: req.body.uid + '.eml'
                        }
                        res.status(200).send(resultado);
                    });
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'generatePDFandSEND', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                //Create PDF file based on parameters
                const agent = new https.Agent({ rejectUnauthorized: false });
                const options = {
                    url: req.body.mailReportURL //url: 'https://localhost/ReportServer?/mktPO_1&rs:format=PDF&sys_user_code=1&sys_user_language=es&sys_user_company=1&row_id=5'
                    ,followRedirect: true
                    ,followAllRedirects: true
                    ,jar: true
                    ,agent: agent
                    ,strictSSL: false
                };
                var stream = request(options).on('error', function(err) {
                    logToFile("Error:  " + JSON.stringify(err))
                    res.status(400).send(err);
                    return;
                }).pipe(fs.createWriteStream((process.env.tempFilesPath + req.body.uid + '.pdf')))

                //create attachments variable AFTER file is created (stream finished)
                stream.on('finish', function (){
                    let attachments = []
                    attachments.push({
                        filename: req.body.rptName + '.pdf'
                        ,path: process.env.tempFilesPath + req.body.uid + '.pdf'
                    })
                    //fix data for MAIL
                    var mailOptions = {
                        from: '"'+req.body.senderName+'" <'+process.env.notifyMailUser+'>', //from debe contener entre <> la misma cuenta que se usa en el Transporter (podría sacarla de [auth.user] )
                        replyTo: req.body.senderMail,
                        to: req.body.destinations.map(x=>x.mail).join(", "),
                        subject: req.body.subjectText,
                        text: req.body.bodyText,
                        html: req.body.bodyText,
                        attachments: attachments
                    };
                    //create Transporter
                    let transporter = nodemailer.createTransport({
                        host: process.env.notifyMailHost,
                        port: process.env.notifyMailPort,
                        secure: process.env.notifyMailSecure,
                        auth: {
                          user: process.env.notifyMailUser,
                          pass: process.env.notifyMailPass,
                        },
                        tls: {
                            rejectUnauthorized: false// do not fail on invalid certs
                        },
                    });
                    //SendMail
                    logToFile("Sending Mail...")
                    transporter.sendMail(mailOptions, (error, info) => {
                        if (error) {
                            logToFile("Error sending mail")
                            logToFile(error)
                            res.status(400).send(error);
                            return;
                        }
                        //logToFile("Message Message: " + info.messageId)
                        
                        logToFile("Message Sent: " + JSON.stringify(info) )
                        logToFile("Deleting File: " + process.env.tempFilesPath + req.body.uid + '.pdf');
                        fs.unlink(process.env.tempFilesPath + req.body.uid + '.pdf', (err) => {
                            if (err) {
                                logToFile("Deleting File error: " + process.env.tempFilesPath + req.body.uid + '.pdf');
                            }
                        });
                        logToFile("Perf spGetMailFormData:  " + ((new Date() - start) / 1000) + ' secs')
                        res.status(200).send(info);
                    });
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//app.post(process.env.iisVirtualPath+'generatePDFandDOWNLOAD', veryfyToken, function(req, res) {
app.get(process.env.iisVirtualPath+'generatePDFandDOWNLOAD', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                //Create PDF file based on parameters
                logToFile("generatePDFandDOWNLOAD:  " + req.query.reportURL)
                const agent = new https.Agent({ rejectUnauthorized: false });
                const options = {
                    url: req.query.reportURL //url: 'https://localhost/ReportServer?/mktPO_1&rs:format=PDF&sys_user_code=1&sys_user_language=es&sys_user_company=1&row_id=5'
                    ,followRedirect: true
                    ,followAllRedirects: true
                    ,jar: true
                    ,agent: agent
                    ,strictSSL: false
                    ,'cache-control': 'no-cache'
                };
                logToFile("Creando:  " + process.env.tempFilesPath + req.query.fileName )
                var stream = request(options).on('error', function(err) {
                    logToFile("Error:  " + JSON.stringify(err))
                    res.status(400).send(err);
                    return;
                //}).pipe(fs.createWriteStream((process.env.tempFilesPath + req.body.uid + '.pdf')))
                }).pipe(fs.createWriteStream((process.env.tempFilesPath + req.query.fileName )))

                //create attachments variable AFTER file is created (stream finished)
                stream.on('finish', function (){
                    logToFile("Creado finish:  " + process.env.tempFilesPath + req.query.fileName )
                    res.download(process.env.tempFilesPath + req.query.fileName)
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysTokensMobileUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('token', sql.NVarChar(sql.MAX), req.body.token )
                .input('deviceData', sql.NVarChar(sql.MAX), req.body.deviceData )
                .execute('spSysTokensMobileUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spSysTokensMobileUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.get(process.env.iisVirtualPath+'pbirsGetPDF', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                //Login to PBIRS and Create PDF file based on parameters
                logToFile("pbirsGetPDF: " + req.query.reportURL)
                httpntlm.get(
                    {
                        url: req.query.reportURL,
                        username: process.env.rptUser,
                        password: process.env.rptPwd,
                        workstation: 'localhost',
                        domain: '',
                        binary: true,
                        strictSSL: false,
                        rejectUnauthorized: false
                    }, function (err, response){
                        if(err){
                            logToFile("error getting pbirs file !!!!!!!!!!!!!!!!!");
                            logToFile(err);
                            res.status(400).send(ex);
                            return;
                        }
                        //Creo Archivo
                        fs.writeFile(
                            (process.env.tempFilesPath + req.query.pdfName)
                            ,response.body
                            ,function (error2) {
                                if(error2){
                                    logToFile("Error creating pbirs pdf file:");
                                    res.status(400).send(error2);
                                    return;
                                }
                                res.download(process.env.tempFilesPath + req.query.pdfName)
                            }
                        )
                    }
                )

            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'pbirsGetEML', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                //Login to PBIRS and Create PDF file based on parameters
                logToFile("pbirsGetEML: " + req.body.mailReportURL)
                httpntlm.get(
                    {
                        url: req.body.mailReportURL,
                        username: process.env.rptUser,
                        password: process.env.rptPwd,
                        workstation: 'localhost',
                        domain: '',
                        binary: true,
                        strictSSL: false,
                        rejectUnauthorized: false
                    }, function (err, response){
                        if(err){
                            logToFile("error getting pbirs_eml file !!!!!!!!!!!!!!!!!");
                            logToFile(err);
                            res.status(400).send(ex);
                            return;
                        }
                        //Creo Archivo PDF
                        fs.writeFile(
                            (process.env.tempFilesPath + req.body.rptName)
                            ,response.body
                            ,function (error2) {
                                if(error2){
                                    logToFile("Error creating pbirs pdf file:");
                                    res.status(400).send(error2);
                                    return;
                                }
                                logToFile("pbirs pdf file created: " + process.env.tempFilesPath + req.body.rptName);
                                
                                //Read attachments
                                let attachments = []
                                let fileData = null;
                                fileData = fs.readFileSync(process.env.tempFilesPath + req.body.rptName);
                                attachments.push({
                                    name: req.body.rptName,
                                    data: fileData,
                                })
                                //fix data for EML generation
                                let destinations = []
                                req.body.destinations.map(x=>{
                                    destinations.push({
                                        //name: x.contactName,
                                        email: x.mail
                                    })
                                })
                                if(destinations.length<=0){
                                    destinations = [{name: req.body.senderMail, email: req.body.senderMail}]
                                }
                                var data = {
                                    from: req.body.senderMail,
                                    headers: { "X-Unsent": "1"},
                                    to: destinations,
                                    subject: req.body.subjectText,
                                    html: req.body.bodyText,
                                    attachments: attachments
                                };
                                //delete PDF
                                fs.unlink(process.env.tempFilesPath + req.body.rptName, (err) => {
                                    if (err) {
                                        logToFile("Deleting File error: " + process.env.tempFilesPath + req.body.rptName);
                                    }
                                    logToFile("File deleted: " + process.env.tempFilesPath + req.body.rptName);
                                });
                                //Generate EML
                                logToFile("Generating EML: " + process.env.tempFilesPath + req.body.uid + '.eml');
                                emlFormat.build(data, function(error, eml) {
                                    if(error){
                                        logToFile("Generating EML Error")
                                        logToFile(error)
                                        res.status(400).send(error);
                                        return;
                                    }
                                    fs.writeFileSync(process.env.tempFilesPath + req.body.uid + '.eml', eml);
                                    logToFile("EML File created: " + process.env.tempFilesPath + req.body.uid + '.eml')
                                    let resultado = {
                                        fileName: 'Mail.eml',
                                        uploadFilename: req.body.uid + '.eml'
                                    }
                                    res.status(200).send(resultado);
                                });

                            }
                        )
                        

                      
                    }
                )

            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'pbirsSendMail', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                //Login to PBIRS and Create PDF file based on parameters
                logToFile("pbirsSendMail: " + req.body.mailReportURL)
                httpntlm.get(
                    {
                        url: req.body.mailReportURL,
                        username: process.env.rptUser,
                        password: process.env.rptPwd,
                        workstation: 'localhost',
                        domain: '',
                        binary: true,
                        strictSSL: false,
                        rejectUnauthorized: false
                    }, function (err, response){
                        if(err){
                            logToFile("error getting pbirs_eml file !!!!!!!!!!!!!!!!!");
                            logToFile(err);
                            res.status(400).send(ex);
                            return;
                        }
                        //Creo Archivo PDF
                        fs.writeFile(
                            (process.env.tempFilesPath + req.body.rptName)
                            ,response.body
                            ,function (error2) {
                                if(error2){
                                    logToFile("Error creating pbirs pdf file:");
                                    res.status(400).send(error2);
                                    return;
                                }
                                logToFile("pbirs pdf file created: " + process.env.tempFilesPath + req.body.rptName);
                                
                                //Read attachments
                                let attachments = []
                                attachments.push({
                                    filename: req.body.rptName
                                    ,path: process.env.tempFilesPath + req.body.rptName
                                })
                                //fix data for MAIL
                                var mailOptions = {
                                    from: '"'+req.body.senderName+'" <'+process.env.notifyMailUser+'>', //from debe contener entre <> la misma cuenta que se usa en el Transporter (podría sacarla de [auth.user] )
                                    replyTo: req.body.senderMail,
                                    to: req.body.destinations.map(x=>x.mail).join(", "),
                                    subject: req.body.subjectText,
                                    text: req.body.bodyText,
                                    html: req.body.bodyText,
                                    attachments: attachments
                                };

                                //create Transporter
                                let transporter = nodemailer.createTransport({
                                    host: process.env.notifyMailHost,
                                    port: process.env.notifyMailPort,
                                    secure: process.env.notifyMailSecure,
                                    auth: {
                                        user: process.env.notifyMailUser,
                                        pass: process.env.notifyMailPass,
                                    },
                                    tls: {
                                        rejectUnauthorized: false// do not fail on invalid certs
                                    },
                                });

                                //SendMail
                                logToFile("Sending Mail...")
                                logToFile("mailOptions: " + JSON.stringify(mailOptions));
                                transporter.sendMail(mailOptions, (error, info) => {
                                    if (error) {
                                        logToFile("Error sending mail")
                                        logToFile(error)
                                        logToFile("Deleting Sending Mail File: " + process.env.tempFilesPath + req.body.rptName);
                                        fs.unlink(process.env.tempFilesPath + req.body.rptName, (err) => {
                                            if (err) {
                                                logToFile("Deleting File error: " + process.env.tempFilesPath + req.body.rptName);
                                            }
                                        });
                                        res.status(400).send(error);
                                        return;
                                    }
                                    //logToFile("Message Message: " + info.messageId)
                                    
                                    logToFile("Message Sent: " + JSON.stringify(info) )
                                    logToFile("Deleting Sending Mail File: " + process.env.tempFilesPath + req.body.rptName);
                                    fs.unlink(process.env.tempFilesPath + req.body.rptName, (err) => {
                                        if (err) {
                                            logToFile("Deleting File error: " + process.env.tempFilesPath + req.body.rptName);
                                        }
                                    });
                                    logToFile("Perf spGetMailFormData:  " + ((new Date() - start) / 1000) + ' secs')
                                    res.status(200).send(info);
                                });
                            }
                        )
                    }
                )

            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})


//#endregion SESSION_OTHERS

//#region DynamicData
app.get(process.env.iisVirtualPath+'spSysModulesSelect', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('sys_user_code', sql.Int, req.query.sys_user_code )
            .input('link_name', sql.VarChar(50), req.query.link_name )
            .execute('spSysModulesSelect', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysModulesSelect:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.get(process.env.iisVirtualPath+'spSysReportsSelect', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userLanguage', sql.VarChar(25), req.query.userLanguage )
            .input('rootName', sql.VarChar(100), req.query.rootName )
            .execute('spSysReportsSelect', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysReportsSelect:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysReportsUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('sys_report_id', sql.VarChar(10), req.body.sys_report_id )
                .input('newAutoOpenState', sql.Bit, req.body.newAutoOpenState )
                .execute('spSysReportsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spSysReportsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.get(process.env.iisVirtualPath+'spSysModulesSelectLookupData', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('sys_user_code', sql.Int, req.query.sys_user_code )
            .input('sys_company_id', sql.Int, req.query.sys_company_id )
            .input('link_name', sql.VarChar(50), req.query.link_name )
            .execute('spSysModulesSelectLookupData', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysModulesSelectLookupData:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.get(process.env.iisVirtualPath+'spSysModulesSelectLookupDataMobile', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('sys_user_code', sql.Int, req.query.sys_user_code )
            .input('sys_company_id', sql.Int, req.query.sys_company_id )
            .input('link_name', sql.VarChar(50), req.query.link_name )
            .execute('spSysModulesSelectLookupDataMobile', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysModulesSelectLookupDataMobile:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'getData', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                //Variables
                let selectPart = ''
                //Get SELECT
                new sql.Request(connectionPool)
                .input('link_name', sql.VarChar(50), req.body.link_name )
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('sys_company_id', sql.Int, req.body.sys_company_id )
                .input('gridDataSkip', sql.BigInt, req.body.gridDataSkip )
                .input('gridNumberOfRows', sql.BigInt, req.body.gridNumberOfRows )
                .input('gridColumns', sql.NVarChar(sql.MAX), req.body.gridColumns )
                .input('filterBy', sql.NVarChar(sql.MAX), req.body.filterBy )
                .input('filterSearch', sql.VarChar(100), req.body.filterSearch )
                .input('sortBy', sql.VarChar(50), req.body.sortBy )
                .input('orderBy', sql.VarChar(50), req.body.orderBy )
                .execute('spGetDataSelect', (err, result) => {
                    if(err){
                        logToFile("DB Error 1:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    try{
                        selectPart = result.recordset[0].selectPart
                        //Run QUERY
                        logToFile("selectPart: " + selectPart)//deja el query en log.txt
                        new sql.Request(connectionPool)
                        .query(selectPart, (err, result) => {
                            if(err){
                                logToFile("DB Error 2:  " + selectPart)
                                logToFile("Error:  " + JSON.stringify(err.originalError.info))
                                res.status(400).send(err.originalError);
                                return;
                            }
                            res.setHeader('content-type', 'application/json');
                            res.status(200).send(result.recordset);
                        })
                    }catch(execp){
                        logToFile('Service Error: ' + JSON.stringify(execp))
                        res.status(400).send(execp);
                        return;
                    }
                })
            }catch(ex){
                logToFile("Service Error:")
                logToFile(JSON.stringify(ex))
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'getDataDX', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                //Variables
                let selectPart = ''
                //Get SELECT
                new sql.Request(connectionPool)
                .input('link_name', sql.VarChar(50), req.body.link_name )
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('sys_company_id', sql.Int, req.body.sys_company_id )
                .input('select', sql.NVarChar(sql.MAX), req.body.select )
                .input('take', sql.BigInt, req.body.take )
                .input('skip', sql.BigInt, req.body.skip )
                .input('searchValue', sql.NVarChar(sql.MAX), req.body.searchValue )
                .input('filter', sql.NVarChar(sql.MAX), req.body.filter )
                .input('sortBy', sql.NVarChar(sql.MAX), req.body.sortBy )
                .execute('spGetDataSelectDX', (err, result) => {
                    if(err){
                        logToFile("DB Error 1:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error:")
                logToFile(JSON.stringify(ex))
                res.status(400).send(ex);
                return;
            }
        }
    })
})

app.post(process.env.iisVirtualPath+'getLookupData', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            let query = ''
            new sql.Request(connectionPool)
            .input('link_name', sql.VarChar(50), req.body.link_name )
            .input('db_column', sql.VarChar(50), req.body.db_column )
            .input('sys_user_code', sql.Int, req.body.sys_user_code )
            .input('sys_company_id', sql.Int, req.body.sys_company_id )
            .execute('spGetModuleColumnSearchData', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spGetModuleColumnSearchData:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                try{
                    logToFile('Query: ' + result.recordset[0].query);
                    query = result.recordset[0].query
                    //Run QUERY
                    new sql.Request(connectionPool)
                    .query(query, (queryError, queryR) => {
                        logToFile("Perf internalQuery:  " + ((new Date() - start) / 1000) + ' secs')
                        if(queryError){
                            logToFile('Database Error inside getLookupData: ' + JSON.stringify(queryError.originalError.info))
                            res.status(400).send(queryError.originalError);
                            return;
                        }
                        res.setHeader('content-type', 'application/json');
                        res.status(200).send(queryR.recordset);
                    })
                }catch(execp){
                    logToFile("Service Error")
                    logToFile(execp)
                    logToFile("Error:  " + JSON.stringify(execp))
                    res.status(400).send(execp);
                    return;
                }
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'getLookupDataDX', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            let query = ''
            new sql.Request(connectionPool)
            .input('link_name', sql.VarChar(50), req.body.link_name )
            .input('db_column', sql.VarChar(50), req.body.db_column )
            .input('sys_user_code', sql.Int, req.body.sys_user_code )
            .input('sys_company_id', sql.Int, req.body.sys_company_id )
            .input('searchValue', sql.VarChar(50), req.body.searchValue )
            .execute('spGetModuleColumnSearchDataDX', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spGetModuleColumnSearchDataDX:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                try{
                    logToFile('Query: ' + result.recordset[0].query);
                    query = result.recordset[0].query
                    //Run QUERY
                    new sql.Request(connectionPool)
                    .query(query, (queryError, queryR) => {
                        logToFile("Perf internalQuery:  " + ((new Date() - start) / 1000) + ' secs')
                        if(queryError){
                            logToFile('Database Error inside getLookupDataDX: ' + JSON.stringify(queryError.originalError.info))
                            res.status(400).send(queryError.originalError);
                            return;
                        }
                        res.setHeader('content-type', 'application/json');
                        res.status(200).send(queryR.recordset);
                    })
                }catch(execp){
                    logToFile("Service Error")
                    logToFile(execp)
                    logToFile("Error:  " + JSON.stringify(execp))
                    res.status(400).send(execp);
                    return;
                }
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysModulesColumnsUserUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('link_name', sql.VarChar(50), req.body.link_name )
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('columns', sql.NVarChar(sql.MAX), req.body.columns )
                .input('shouldWrapCellText', sql.Bit, req.body.shouldWrapCellText )
                .input('tableLines', sql.VarChar(50), req.body.tableLines )
                .execute('spSysModulesColumnsUserUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spSysModulesColumnsUserUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysModulesFiltersUserUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('link_name', sql.VarChar(50), req.body.link_name )
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('filter_id', sql.Int, req.body.filter_id )
                .input('name', sql.VarChar(250), req.body.name )
                .input('conditions', sql.NVarChar(sql.MAX), req.body.conditions )
                .execute('spSysModulesFiltersUserUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spSysModulesFiltersUserUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysModulesFiltersUserDelete', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('link_name', sql.VarChar(50), req.body.link_name )
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('filter_id', sql.Int, req.body.filter_id )
                .execute('spSysModulesFiltersUserDelete', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spSysModulesFiltersUserDelete:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysModulesFiltersUserDefaultUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('link_name', sql.VarChar(50), req.body.link_name )
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('filter_id', sql.Int, req.body.filter_id )
                .input('is_system', sql.Bit, req.body.is_system )
                .execute('spSysModulesFiltersUserDefaultUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spSysModulesFiltersUserDefaultUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion DynamicData

//#region USERS
app.get(process.env.iisVirtualPath+'spSysUsersSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spSysUsersSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysUsersSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysUsersUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.NVarChar(sql.MAX), req.body.editRecord )
                .execute('spSysUsersUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spSysUsersUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysUsersPreferencesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('user_data', sql.NVarChar(sql.MAX), req.body.user_data )
                .execute('spSysUsersPreferencesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spSysUsersPreferencesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'sp_sys_user_picture_upload', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('original_file_name', sql.VarChar(500), req.body.original_file_name )
                .input('file_type', sql.NVarChar(sql.MAX), req.body.file_type )
                .input('file_size', sql.VarChar(sql.Int), req.body.file_size )
                .input('editing_sys_user_code', sql.VarChar(sql.Int), req.body.editing_sys_user_code )
                .execute('sp_sys_user_picture_upload', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    //NO quiero registrar la imagen logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf sp_sys_user_picture_upload:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion USERS

//#region PROFILES
app.get(process.env.iisVirtualPath+'spSysProfilesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spSysProfilesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysProfilesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysProfilesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('userLanguage', sql.VarChar(50), req.body.userLanguage )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.NVarChar(sql.MAX), req.body.editRecord )
                .execute('spSysProfilesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spSysProfilesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion PROFILES

//#region COMPANIES
app.get(process.env.iisVirtualPath+'spSysCompaniesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spSysCompaniesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysCompaniesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysCompaniesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.NVarChar(sql.MAX), req.body.editRecord )
                .execute('spSysCompaniesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spSysCompaniesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion COMPANIES

//#region MODULES
app.get(process.env.iisVirtualPath+'spSysModulesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spSysModulesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysModulesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysModulesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.NVarChar(sql.MAX), req.body.editRecord )
                .execute('spSysModulesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spSysModulesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion MODULES

//#region NOTIFICATIONS
app.get(process.env.iisVirtualPath+'spNotificationsSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spNotificationsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spNotificationsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spNotificationsUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.NVarChar(sql.MAX), req.body.editRecord )
                .execute('spNotificationsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spNotificationsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion NOTIFICATIONS

////#region CHOFER
app.get(process.env.iisVirtualPath+'spChoferesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spChoferesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spChoferesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spChoferesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.NVarChar(sql.MAX), req.body.editRecord )
                .execute('spChoferesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spChoferesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion CHOFER


//#region PARTNERS
app.get(process.env.iisVirtualPath+'spPartnerMasterSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spPartnerMasterSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spPartnerMasterSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spPartnerMasterUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.NVarChar(sql.MAX), req.body.editRecord )
                .execute('spPartnerMasterUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spPartnerMasterUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion PARTNERS

//#region PARTNERS_GROUPS
app.get(process.env.iisVirtualPath+'spPartnerMasterGroupsSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spPartnerMasterGroupsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spPartnerMasterGroupsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spPartnerMasterGroupsUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.NVarChar(sql.MAX), req.body.editRecord )
                .execute('spPartnerMasterGroupsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spPartnerMasterGroupsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion PARTNERS_GROUPS

//#region ITEMS
app.get(process.env.iisVirtualPath+'spInvMasterSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spInvMasterSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spInvMasterSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spInvMasterUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.NVarChar(sql.MAX), req.body.editRecord )
                .execute('spInvMasterUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spInvMasterUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion ITEMS

//#region ITEMS_GROUPS
app.get(process.env.iisVirtualPath+'spInvMasterGroupsSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spInvMasterGroupsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spInvMasterGroupsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spInvMasterGroupsUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.NVarChar(sql.MAX), req.body.editRecord )
                .execute('spInvMasterGroupsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spInvMasterGroupsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion ITEMS_GROUPS

//#region WAREHOUSES
app.get(process.env.iisVirtualPath+'spWhMasterSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spWhMasterSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spWhMasterSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spWhMasterUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.NVarChar(sql.MAX), req.body.editRecord )
                .execute('spWhMasterUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spWhMasterUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion WAREHOUSES

//#region UoM
app.get(process.env.iisVirtualPath+'spInvMasterUoMSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spInvMasterUoMSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spInvMasterUoMSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spInvMasterUoMUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.NVarChar(sql.MAX), req.body.editRecord )
                .execute('spInvMasterUoMUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spInvMasterUoMUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion UoM

//#region BRANDS
app.get(process.env.iisVirtualPath+'spInvMasterBrandsSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spInvMasterBrandsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spInvMasterBrandsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spInvMasterBrandsUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.NVarChar(sql.MAX), req.body.editRecord )
                .execute('spInvMasterBrandsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spInvMasterBrandsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion BRANDS

//#region INVTYPES
app.get(process.env.iisVirtualPath+'spinvMasterTypesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spinvMasterTypesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spinvMasterTypesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spinvMasterTypesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.NVarChar(sql.MAX), req.body.editRecord )
                .execute('spinvMasterTypesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spinvMasterTypesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion INVTYPES

//#region SDE(Holcim)
app.post(process.env.iisVirtualPath+'sde_GetTag_Out_Sync', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                logToFile('running sde_GetTag_Out_Sync')
                const url = 'https://dev.laseritsconline.com:47489/XISOAPAdapter/MessageServlet?senderParty=PEGASUS_GUARDIA&senderService=EC_PEGASUS&receiverParty=&receiverService=CSQCLNT400&interface=GetTag_Out_Sync&interfaceNamespace=urn:com:lh:logistics:la:pegasus:guardia';
                const sampleHeaders = {
                    'user-agent': 'pegasus',
                    'Content-Type': 'text/xml;charset=UTF-8',
                    'soapAction': 'http://sap.com/xi/WebService/soap1.1',
                    'Authorization': 'Basic cGVnYXN1czpMc3JAMjAxMw=='
                };
                const xmlRequest = req.body.xmlRequest
                logToFile(req.body.xmlRequest)
                soapRequest(
                    { url: url, headers: sampleHeaders, xml: xmlRequest, timeout: 2000 }
                ).then((respuesta)=>{
                    const { response } = respuesta;
                    const { headers, body, statusCode } = response;
                    logToFile(JSON.stringify(headers))
                    logToFile(body)
                    logToFile(statusCode)
                    res.status(statusCode).send(body);
                }).catch((errorWS)=>{
                    logToFile("errorWS")
                    logToFile(errorWS)
                    res.status(400).send(errorWS);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'sde_PlantTimesV03_Out_Sync', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                const url = 'https://dev.laseritsconline.com:47489/XISOAPAdapter/MessageServlet?senderParty=PEGASUS_PLANTA&senderService=EC_PEGASUS&receiverParty=&receiverService=&interface=PlantTimesV03_Out_Sync&interfaceNamespace=urn:com:lh:logistics:la:pegasus:planta';
                const sampleHeaders = {
                    'user-agent': 'pegasus',
                    'Content-Type': 'text/xml;charset=UTF-8',
                    'soapAction': 'http://sap.com/xi/WebService/soap1.1',
                    'Authorization': 'Basic cGVnYXN1czpMc3JAMjAxMw=='
                };
                const xmlRequest = req.body.xmlRequest
                //<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:lh:logistics:la:pegasus:planta"> <soapenv:Header/> <soapenv:Body> <urn:PlantTimesV03Request> <PAIS>EC</PAIS> <CENTRO>ACB0</CENTRO> <FECHA>2021-06-18</FECHA> <HORA>09:35:12</HORA> <IDANTENA>ACVIGIN</IDANTENA> <IDTAG>EGSI2736</IDTAG> <PESO></PESO> <PRECINTOS></PRECINTOS> <PESO_MANUAL></PESO_MANUAL> <PESO_TANDEM> <CAPAC></CAPAC> </PESO_TANDEM> <TKNUM>63401533</TKNUM> <PESO_TARA_1_PARC></PESO_TARA_1_PARC> <PESO_BRUTO_1_PARC></PESO_BRUTO_1_PARC> <PESO_TARA_2_PARC></PESO_TARA_2_PARC> <PESO_BRUTO_2_PARC></PESO_BRUTO_2_PARC> <VBELN>330101406</VBELN> <PRECINTOS_2></PRECINTOS_2> <PONTO_CARGA></PONTO_CARGA> <CONTINGENCIA></CONTINGENCIA> <T_DADOS_ENTREGA> <VBELN>330102016</VBELN> <REF_EXT>X1234</REF_EXT> </T_DADOS_ENTREGA> </urn:PlantTimesV03Request> </soapenv:Body> </soapenv:Envelope>
                //const xmlRequest = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:lh:logistics:la:pegasus:planta"> <soapenv:Header/> <soapenv:Body> <urn:PlantTimesV03Request> <PAIS>EC</PAIS> <CENTRO>ACB0</CENTRO> <FECHA>2021-06-18</FECHA> <HORA>09:35:12</HORA> <IDANTENA>ACVIGIN</IDANTENA> <IDTAG>EGSI2736</IDTAG> <PESO></PESO> <PRECINTOS></PRECINTOS> <PESO_MANUAL></PESO_MANUAL> <PESO_TANDEM> <CAPAC></CAPAC> </PESO_TANDEM> <TKNUM>63401533</TKNUM> <PESO_TARA_1_PARC></PESO_TARA_1_PARC> <PESO_BRUTO_1_PARC></PESO_BRUTO_1_PARC> <PESO_TARA_2_PARC></PESO_TARA_2_PARC> <PESO_BRUTO_2_PARC></PESO_BRUTO_2_PARC> <VBELN>330101406</VBELN> <PRECINTOS_2></PRECINTOS_2> <PONTO_CARGA></PONTO_CARGA> <CONTINGENCIA></CONTINGENCIA> <T_DADOS_ENTREGA> <VBELN>330102016</VBELN> <REF_EXT>X1234</REF_EXT> </T_DADOS_ENTREGA> </urn:PlantTimesV03Request> </soapenv:Body> </soapenv:Envelope>'
                logToFile('running sde_PlantTimesV03_Out_Sync')
                logToFile(req.body.xmlRequest)
                soapRequest(
                    { url: url, headers: sampleHeaders, xml: xmlRequest, timeout: 2000 }
                ).then((respuesta)=>{
                    const { response } = respuesta;
                    const { headers, body, statusCode } = response;
                    logToFile(JSON.stringify(headers))
                    logToFile(body)
                    logToFile(statusCode)
                    res.status(statusCode).send(body);
                }).catch((errorWS)=>{
                    logToFile("errorWS")
                    logToFile(errorWS)
                    res.status(400).send(errorWS);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion SDE(Holcim)

const server = app.listen(process.env.PORT);
logToFile('API started using port ' + process.env.PORT)

/*
//#region WebSocket
function addWebsocketConnection(newConnection){
    try{
        let fileContent = JSON.parse(fs.readFileSync(process.env.websocketsFile));
        fileContent.connections.push(newConnection)
        fs.writeFileSync(process.env.websocketsFile,JSON.stringify(fileContent))
    }catch(ex){
        logToFile('xxx Error en addWebsocketConnection xxx');
        logToFile(JSON.stringify(ex));
    }
}
function removeWebsocketConnection(userID){
    try{
        let fileContent = JSON.parse(fs.readFileSync(process.env.websocketsFile));
        fileContent.connections = fileContent.connections.filter(x => x.userData.userCode != userID)
        fs.writeFileSync(process.env.websocketsFile,JSON.stringify(fileContent))
    }catch(ex){
        logToFile('xxx Error en removeWebsocketConnection xxx');
        logToFile(JSON.stringify(ex));
    }
}


//#region CreateServer
logToFile('Starting Websocket Server...');
const WebSocketServer = new WebSocket.Server({server})//initialize the WebSocket server instance
logToFile('!!!!!!!!!!!!!!!!!!!!Websocket Server created!!');
let startfileContent = {connections:[]};
fs.writeFileSync(process.env.websocketsFile,JSON.stringify(startfileContent))
logToFile('!!!!!!!!!!!!!!!!!!!!Websocket Server file restarted!!');
//#endregion CreateServer

WebSocketServer.on('connection', (ws,request) => {   
    let startIndex = parseInt(request.url.indexOf('userid'));
    startIndex = startIndex + 7;
    let userID = request.url.substring(startIndex,1000)
    let wsID = request.headers['sec-websocket-key']
    let userData = {
         "userCode": userID
        ,"wsID": wsID
    }
    ws['userData'] = userData
    addWebsocketConnection(ws)

    ws.on('message', message => {
        let fileContent = JSON.parse(fs.readFileSync(process.env.websocketsFile));
        //ws.send(message)//send message to All

        WebSocketServer.clients.forEach(function each(client) {
            //valida que exista, y que usuario esté en archivo de conexiones
            if (client.readyState === WebSocket.OPEN && fileContent.connections.some(x=>x.userData.userCode==client.userData.userCode)) {
                logToFile('Enviar mensaje:' + client.userData.userCode);
                client.send(message);
            }
        });
    });

    ws.on('close', (reasonCode,userData) => {
        removeWebsocketConnection(userData)
    })
})
//#endregion WebSocket
*/