import mongoose from 'mongoose';
import { Role, RoleSchema } from '../schemas/role.schema';

const defaultRoles = [
  {
    roleId: 'Maker',
    roleName: 'Maker',
    // SSH password for the maker@<host> account. Replace with the real one.
    passKey: 'maker001',
  },
  {
    roleId: 'Checker',
    roleName: 'Checker',
    // SSH password for the checker@<host> account. Replace with the real one.
    passKey: 'checker001',
  },
];

async function seedRoles() {
  await mongoose.connect('mongodb://localhost:27017/secureX');

  const RoleModel = mongoose.model(Role.name, RoleSchema);

  await RoleModel.deleteMany({});
  // Drops indexes no longer in the schema (e.g. the old unique passKey index).
  await RoleModel.syncIndexes();
  const inserted = await RoleModel.insertMany(defaultRoles);

  console.log('Seeded roles:', inserted.map((role) => role.roleName).join(', '));
}

seedRoles()
  .then(() => mongoose.disconnect())
  .catch((error) => {
    console.error('Role seed failed:', error);
    mongoose.disconnect().finally(() => process.exit(1));
  });
