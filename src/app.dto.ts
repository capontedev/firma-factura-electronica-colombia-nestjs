import { ApiProperty } from '@nestjs/swagger';

export class ConfigDTO {
  @ApiProperty({
    description: 'Ruta archivo .p12'
  })
  ruta: string; 

  @ApiProperty({
    description: 'Clave archivo .p12'
  })
  clave: string; 
}

class BaseDTO {
  @ApiProperty({
    description: 'empresa creada en config.json'
  })
  empresa: string;
}

export class FirmaDTO extends BaseDTO {
  @ApiProperty({
    description: 'xml a firmar codificado base64'
  })
  xml: string;
}

export class VerificarDTO extends BaseDTO {}
