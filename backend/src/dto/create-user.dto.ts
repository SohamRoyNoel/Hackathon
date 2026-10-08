import { Type, Transform } from 'class-transformer';
import {
  ArrayNotEmpty,
  IsArray,
  IsBoolean,
  IsString,
  ValidateNested,
} from 'class-validator';

export class CreateUserDto {
  @IsString()
  userName!: string;

  @IsArray()
  @ArrayNotEmpty()
  @IsString({ each: true })
  @Transform(({ value }) => (Array.isArray(value) ? value : [value]))
  role!: string[];

  @IsBoolean()
  @Transform(({ value }) => value === true || value === 'true')
  shouldIncludeScan!: boolean;
}
