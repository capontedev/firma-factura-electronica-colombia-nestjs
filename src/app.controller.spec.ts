import { Test, TestingModule } from '@nestjs/testing';
import { AppController } from './app.controller';
import { Response } from 'express';
import { AppService } from './app.service';
import * as path from 'path';
import * as fs from 'fs';
import { jsonXML, jsonVerificar } from '../assets-test/resp';

describe('AppController', () => {
  let appService: AppService;
  let appController: AppController;

  const mockResponse = (): Partial<Response> => {
    const res: Partial<Response> = {};
    res.status = jest.fn().mockReturnValue(res);
    res.send = jest.fn().mockReturnValue(res);
    return res;
  };

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      controllers: [AppController],
      providers: [AppService],
    }).compile();

    appService = app.get<AppService>(AppService);
    appController = app.get<AppController>(AppController);

    jest.spyOn(appService, 'cargarConfig').mockImplementation((attr: string) => ({
      clave: '123456',
      ruta: path.resolve(__dirname + './../assets-test/Certificado.p12')
    }));
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('root', () => {
    it('should return signed xml', async () => {
      jest.spyOn(appService, 'getDate').mockImplementation((date: Date) => new Date(new Date('01-01-2023').toUTCString().slice(0, -4)));
      jest.spyOn(appService, 'generateId').mockImplementation(() => 'my-id');

      let xml = fs.readFileSync(path.resolve(__dirname + './../assets-test/factura.xml'), { encoding: 'utf-8' });
      xml = Buffer.from(xml).toString('base64');

      const response = mockResponse();
      const body = {
        empresa: 'empresa-prueba',
        xml
      }

      await appController.firmar(response as Response, body);

      expect(response.send).toHaveBeenCalledWith(JSON.parse(jsonXML));
    });

    it('should verify p12 file', async () => {
      const body = {
        empresa: 'empresa-prueba'
      }

      const response = mockResponse();

      await appController.verificarCertificado(response as Response, body);

      expect(response.send).toHaveBeenCalledWith(JSON.parse(jsonVerificar));
    });
  });
});
