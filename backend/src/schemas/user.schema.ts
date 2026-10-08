import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Schema as MongooseSchema, Types } from 'mongoose';

export type UserDocument = HydratedDocument<User>;

@Schema({ collection: 'users', timestamps: true })
export class User {
  @Prop({ required: true })
  userName!: string;

  @Prop({
    type: [{ type: MongooseSchema.Types.ObjectId, ref: 'Role' }],
    required: true,
    default: [],
  })
  roleId!: Types.ObjectId[];
}

export const UserSchema = SchemaFactory.createForClass(User);
