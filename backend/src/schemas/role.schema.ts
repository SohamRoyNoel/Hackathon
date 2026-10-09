import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type RoleDocument = HydratedDocument<Role>;

@Schema({ collection: 'roles', timestamps: true })
export class Role {
  @Prop({ required: true, unique: true })
  roleId!: string;

  @Prop({ required: true, unique: true })
  roleName!: string;

  // SSH password used by the post-agent step (sshpass -p <passKey>).
  @Prop()
  passKey?: string;
}

export const RoleSchema = SchemaFactory.createForClass(Role);
