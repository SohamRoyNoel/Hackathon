import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type DataAccessType = 'R' | 'W' | 'RW' | 'NA';

export type RoleAccess = {
  businessData: DataAccessType;
  salesData: DataAccessType;
  topSecretData: DataAccessType;
};

export type RoleDocument = HydratedDocument<Role>;

@Schema({ collection: 'roles', timestamps: true })
export class Role {
  @Prop({ required: true, unique: true })
  roleId!: string;

  @Prop({ required: true, unique: true })
  roleName!: string;

  @Prop({
    type: {
      businessData: {
        type: String,
        enum: ['R', 'W', 'RW', 'NA'],
        default: 'NA',
      },
      salesData: {
        type: String,
        enum: ['R', 'W', 'RW', 'NA'],
        default: 'NA',
      },
      topSecretData: {
        type: String,
        enum: ['R', 'W', 'RW', 'NA'],
        default: 'NA',
      },
    },
    _id: false,
    required: true,
  })
  access!: RoleAccess;

  @Prop({ default: false })
  isScanned!: boolean;
}

export const RoleSchema = SchemaFactory.createForClass(Role);
