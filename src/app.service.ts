import { Injectable } from '@nestjs/common';
import * as xmldsig from 'xmldsigjs';
import * as fs from 'fs';
import * as path from 'path';
import * as x509Lib from '@peculiar/x509';
import { Crypto } from '@peculiar/webcrypto';
import * as xades from 'xadesjs';
import * as xmlCore from 'xml-core';
import { Convert } from 'pvtsutils';
import * as forge from 'node-forge';
import { hexToDec } from './utils';
import { Buffer } from 'buffer';
import { ConfigDTO, FirmaDTO, VerificarDTO } from './app.dto';

@Injectable()
export class AppService {
  cargarConfig(attr: string): ConfigDTO {
    const fileContent = fs.readFileSync( path.resolve(__dirname, 'config.json') , { encoding: 'utf8' });
    const json = JSON.parse(fileContent);     

    if (json) {
      const attrs = json[attr];

      if (attrs) {
        return attrs;
      } else {
        throw `No se puede leer los atributos de ${attr} en el archivo config.json.`;  
      }
    } else {
      throw 'No se puede leer el archivo config.json.';
    }
  }

  getDate(date: Date): Date {
    return new Date(date.toUTCString().slice(0, -4))
  }

  private pemToBase64 = (pem: string, extractBreak: boolean = true) => {
    let resp = pem;
    if (extractBreak) resp = resp.replace(/[\r\n]/g, '');
    return resp.replace(/-----(BEGIN|END)[\w\d\s]+-----/g, '')
  }

  private leerP12 = (ruta: string, clave: string) => {
    try {
      const keyFile = fs.readFileSync(ruta, { encoding: 'binary' });

      //Separar el p12
      const asn = forge.asn1.fromDer(keyFile);
      const p12 = forge.pkcs12.pkcs12FromAsn1(asn, true, clave);
      //Leer Key Data
      const keyData = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag].concat(p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag]);
      //Leer Clave Privada
      const rsaPrivateKey = forge.pki.privateKeyToAsn1(keyData[0].key);
      const privateKeyInfo = forge.pki.wrapRsaPrivateKey(rsaPrivateKey);
      const pemPrivate = forge.pki.privateKeyInfoToPem(privateKeyInfo);
      const pkey64 = this.pemToBase64(pemPrivate);
      //Leer Cert
      const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag];
      const expiresOn = certBags[0].cert.validity.notAfter as Date;

      let certs64: string[] = [];
      for (let i = 0; i < certBags.length; i++) {
        const extraCert = forge.pki.certificateToPem(certBags[i].cert);
        certs64.push(this.pemToBase64(extraCert));
      }
      const certx509 = forge.pki.certificateToPem(certBags[0].cert);
      const x509Cert = this.pemToBase64(certx509, false);
      //Leer clave publica desde la clave privada 
      const preprivateKey = forge.pki.privateKeyFromPem(pemPrivate);
      const prepublicKey  = forge.pki.rsa.setPublicKey(preprivateKey.n, preprivateKey.e);
      const publicKey = forge.pki.publicKeyToPem(prepublicKey);
      const pbkey64 = this.pemToBase64(publicKey)
      
      //return the data
      return {
        x509Cert,
        pkey64,
        pbkey64,
        certs64,
        expiresOn
      };
    } catch (err) {
      throw 'Error en la llave criptográfica y clave de la misma.';
    }
  }
  

  generateId()  {
    return (`${1e7}-${1e3}-${4e3}-${8e3}-${1e11}`).replace(/[018]/g, (c: any) =>
      (c ^ (crypto.getRandomValues(new Uint8Array(1)))[0] & 15 >> c / 4).toString(16)
      );
  }

  async firmar(body: FirmaDTO) {
    try {
      const config = this.cargarConfig(body.empresa);
      body.xml = Buffer.from(body.xml, 'base64').toString('utf8');

      const {
        x509Cert,
        pbkey64: pb,
        pkey64: pk,
        certs64: certs
      } = this.leerP12(config.ruta, config.clave);
            
      const crypto = new Crypto();
      x509Lib.cryptoProvider.set(crypto);
      xades.Application.setEngine('NodeJS', crypto);

      const referenceId = this.generateId();
      const hash = 'SHA-256';
      const alg = {
        name: 'RSASSA-PKCS1-v1_5',
        hash,
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength: 2048,
      }
      const keys = await crypto.subtle.generateKey(alg, false, ['sign', 'verify']);

      // Leer el certificado
      const certDer = Convert.FromBase64(certs[0]);
      // Leer llave publica
      const publicKeyDer = Convert.FromBase64(pb);
      const publicKey = await crypto.subtle.importKey('spki', publicKeyDer, alg, true, ['verify']);
  
      // Leer clave privada
      const keyDer = Convert.FromBase64(pk);
      const key = await crypto.subtle.importKey('pkcs8', keyDer, alg, false, ['sign']);

      //Prueba 1
      //xmlToSign = fs.readFileSync(path.join(__dirname, 'prueba.xml'), { encoding: 'utf8' })
      
      // XAdES-EPES
      let xml = xades.Parse(body.xml);
      const xadesXml = new xades.SignedXml();

      xadesXml.XmlSignature.KeyInfo.Id = 'xmldsig-'+referenceId+'-keyinfo';

      // Set Id for SignedProperties
      xadesXml.SignedProperties.Id = 'xmldsig-'+referenceId+'-signedprops';

      async function addSigningCert(signedXml: xades.SignedXml, certPEM: string, hash = 'SHA-256') {
        const cert = new x509Lib.X509Certificate(certPEM);
        const signedProperties = signedXml.SignedProperties;
      
        const xmlCert = new xades.xml.Cert();
        xmlCert.IssuerSerial.X509IssuerName = cert.issuer.split(', ').reverse().join(',');
        xmlCert.IssuerSerial.X509SerialNumber = hexToDec(cert.serialNumber);
        
        const alg = xmldsig.CryptoConfig.GetHashAlgorithm(hash);
        xmlCert.CertDigest.DigestMethod.Algorithm = alg.namespaceURI;
        const thumbprint = await cert.getThumbprint(hash);
        xmlCert.CertDigest.DigestValue = new Uint8Array(thumbprint);
      
        signedProperties.SignedSignatureProperties.SigningCertificate.Add(xmlCert)
      }

      // Extraer certificados
      for (const cert of certs) {
        await addSigningCert(xadesXml, cert);
      }     

      //Agregando public chain en x509Data bloque de KeyInfo
      const x509Data = new xmldsig.KeyInfoX509Data();
      const cert = new x509Lib.X509Certificate(certs[0]);
      x509Data.AddCertificate(new xmldsig.X509Certificate(cert.rawData));
      xadesXml.XmlSignature.KeyInfo.Add(x509Data)

      const policyId = new xades.xml.SignaturePolicyId();
      policyId.SigPolicyId = new xades.xml.SigPolicyId ();
      policyId.SigPolicyId.Identifier = new xades.xml.Identifier();
      policyId.SigPolicyId.Identifier.Value = 'https://facturaelectronica.dian.gov.co/politicadefirma/v2/politicadefirmav2.pdf';
      policyId.SigPolicyId.Description = 'Política de firma para facturas electrónicas de la República de Colombia.';
      policyId.SigPolicyHash = new xades.xml.SigPolicyHash();
      policyId.SigPolicyHash.DigestMethod = new xmldsig.DigestMethod();
      policyId.SigPolicyHash.DigestMethod.Algorithm = 'http://www.w3.org/2001/04/xmlenc#sha256';
      policyId.SigPolicyHash.DigestValue = Buffer.from('dMoMvtcG5aIzgYo0tIsSQeVJBDnUnfSOfBpxXrmor0Y=', 'base64');
      xadesXml.Properties.SignedProperties.SignedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyImplied = false;
      xadesXml.Properties.SignedProperties.SignedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyId = policyId;

      //Crear firma
      const signature = await xadesXml.Sign( //Signing document
        alg,                                 //algorithm
        key,                                 //key
        xml,                                 //document
      {                                      //options
        keyValue: publicKey,
        id: 'xmldsig-'+referenceId,
        signerRole: {
          claimed: ['supplier'],
        },
        references: [
          { 
            id: 'xmldsig-'+referenceId+'-ref0',
            uri: '',
            hash, 
            transforms: ['enveloped'] 
          },
          { hash, uri: '#xmldsig-'+referenceId+'-keyinfo' }
        ],
        signingTime: {
          format: 'yyyy-mm-dd"T"hh:mm:ss.l"-05:00"',
          value: this.getDate(new Date())
        },
      });

      // Agregar firma a XML
      const extensionContent = xml.getElementsByTagName('ext:ExtensionContent');
      if (!extensionContent.length) {
        throw 'No se puede agregar la firma no existe ExtensionContent en el XML';
      }

      const signatureValue = signature.GetXml().getElementsByTagName(`ds:SignatureValue`);
      if (signatureValue.length) {
        signatureValue[0].setAttribute('Id', 'xmldsig-'+referenceId+'-sigvalue');
      }

      const qualifyingProperties = signature.GetXml().getElementsByTagName(`xades:QualifyingProperties`)
      if (qualifyingProperties.length) {
        qualifyingProperties[0].setAttribute('xmlns:xades', 'http://uri.etsi.org/01903/v1.3.2#');
			  qualifyingProperties[0].setAttribute('xmlns:xades141', 'http://uri.etsi.org/01903/v1.4.1#');
        qualifyingProperties[0].setAttribute('Target', '#xmldsig-'+referenceId);
      }
    
      extensionContent[extensionContent.length-1].appendChild(signature.GetXml());

      // Serializar XML
      const sXML = xmlCore.Stringify(xml);

      //Prueba 2
      //fs.writeFileSync(path.join(__dirname, 'xmlfirmado.xml'), sXML, { encoding: 'utf8'});

      return Buffer.from(sXML).toString('base64'); 
    } catch (err) {
      console.log(err);
      throw err;
    }
  }

  verificarCertificado(body: VerificarDTO) {
    const config = this.cargarConfig(body.empresa);

    function getSecondsDiff(startDate: Date, endDate: Date) {
      const msInSecond = 1000;
    
      return Math.round(
        Math.abs(endDate.getTime() - startDate.getTime()) / msInSecond,
      );
    }

    let { expiresOn } = this.leerP12(config.ruta, config.clave);

    let isValid = true;
    let timediff = getSecondsDiff(new Date(expiresOn), new Date());
    if (timediff < 100000 ) {
       isValid = false;
    }

    return {
      isValid,
      expiresOn: expiresOn.toISOString() 
    };
  }
}