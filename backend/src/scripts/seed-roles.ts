import mongoose from 'mongoose';
import { Role, RoleSchema } from '../schemas/role.schema';

const defaultRoles = [
  {
    roleId: 'Role001',
    roleName: 'Role001',
    passKey: 'pass001',
    access: {
      businessData: 'R',
      salesData: 'R',
      topSecretData: 'NA',
    },
    isScanned: false,
  },
  {
    roleId: 'Role002',
    roleName: 'Role002',
    passKey: 'pass002',
    access: {
      businessData: 'RW',
      salesData: 'R',
      topSecretData: 'NA',
    },
    isScanned: false,
  },
  {
    roleId: 'Role003',
    roleName: 'Role003',
    passKey: 'pass003',
    access: {
      businessData: 'R',
      salesData: 'RW',
      topSecretData: 'NA',
    },
    isScanned: false,
  },
  {
    roleId: 'Role004',
    roleName: 'Role004',
    passKey: 'pass004',
    access: {
      businessData: 'RW',
      salesData: 'RW',
      topSecretData: 'NA',
    },
    isScanned: false,
  },
  {
    roleId: 'CEO',
    roleName: 'CEO',
    passKey: 'passceo',
    access: {
      businessData: 'RW',
      salesData: 'RW',
      topSecretData: 'RW',
    },
    isScanned: false,
  },
];

async function seedRoles() {
  await mongoose.connect('mongodb://localhost:27017/secureX');

  const RoleModel = mongoose.model(Role.name, RoleSchema);

  await RoleModel.deleteMany({});
  const inserted = await RoleModel.insertMany(defaultRoles);

  console.log('Seeded roles:', inserted.map((role) => role.roleName).join(', '));
}

seedRoles()
  .then(() => mongoose.disconnect())
  .catch((error) => {
    console.error('Role seed failed:', error);
    mongoose.disconnect().finally(() => process.exit(1));
  });
