import { Body, Controller, Post, Res, HttpStatus, HttpException } from '@nestjs/common';
import { AppService } from './app.service';
import { Response } from 'express';
import { ApiBody, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { FirmaDTO, VerificarDTO } from './app.dto';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Post('firmar')
  @ApiOperation({ summary: 'Firmar Documento' })
  @ApiBody({ type: FirmaDTO })
  @ApiResponse({ status: 200, description: 'Documento Firmando en Base64' })
  async firmar(@Res() response: Response, @Body() body: FirmaDTO) {
    try {
      const signedXML = await this.appService.firmar(body);
      response.status(200).send({xml: signedXML});
    } catch (error) {
      console.log(error)
      throw new HttpException({
        status: HttpStatus.INTERNAL_SERVER_ERROR,
        error,
      }, HttpStatus.INTERNAL_SERVER_ERROR);
    }    
  }

  @Post('verificar-certificado')
  @ApiOperation({ summary: 'Verifica si el verificado .p12 es valido' })
  @ApiBody({ type: VerificarDTO })
  @ApiResponse({ status: 200, description: 'Estatus del certificado .p12' })
  async verificarCertificado(@Res() response: Response, @Body() body: VerificarDTO) {
    try {
      const verify = this.appService.verificarCertificado(body);
      response.status(200).send(verify);
    } catch (error) {
      throw new HttpException({
        status: HttpStatus.INTERNAL_SERVER_ERROR,
        error,
      }, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
