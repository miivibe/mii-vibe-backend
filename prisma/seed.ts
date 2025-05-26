import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Seeding database...');

  // Clean up existing data
  await prisma.securityEvent.deleteMany();
  await prisma.loginAttempt.deleteMany();
  await prisma.otpCode.deleteMany();
  await prisma.userSession.deleteMany();
  await prisma.passwordHistory.deleteMany();
  await prisma.trustedDevice.deleteMany();
  await prisma.rateLimit.deleteMany();
  await prisma.user.deleteMany();

  // Create admin user
  const adminSalt = await bcrypt.genSalt(12);
  const adminPassword = 'Admin@123456';
  const adminPasswordHash = await bcrypt.hash(adminPassword + adminSalt, 12);

  const adminUser = await prisma.user.create({
    data: {
      email: 'admin@miichisoft.com',
      username: 'admin',
      passwordHash: adminPasswordHash,
      salt: adminSalt,
      firstName: 'Admin',
      lastName: 'User',
      isActive: true,
      isVerified: true,
      twoFactorEnabled: false,
    }
  });

  // Create test users
  const testUsers = [
    {
      email: 'john.doe@miichisoft.com',
      username: 'johndoe',
      firstName: 'John',
      lastName: 'Doe',
      twoFactorEnabled: true,
    },
    {
      email: 'jane.smith@miichisoft.net',
      username: 'janesmith',
      firstName: 'Jane',
      lastName: 'Smith',
      twoFactorEnabled: false,
    },
    {
      email: 'bob.wilson@miichisoft.com',
      username: 'bobwilson',
      firstName: 'Bob',
      lastName: 'Wilson',
      twoFactorEnabled: true,
    }
  ];

  for (const userData of testUsers) {
    const salt = await bcrypt.genSalt(12);
    const password = 'Test@123456';
    const passwordHash = await bcrypt.hash(password + salt, 12);

    await prisma.user.create({
      data: {
        ...userData,
        passwordHash,
        salt,
        isActive: true,
        isVerified: true,
      }
    });
  }

  // Create some sample security events
  await prisma.securityEvent.createMany({
    data: [
      {
        userId: adminUser.id,
        eventType: 'LOGIN_SUCCESS',
        severity: 'LOW',
        description: 'Admin user logged in successfully',
        ipAddress: '192.168.1.100',
      },
      {
        eventType: 'LOGIN_FAILED',
        severity: 'MEDIUM',
        description: 'Failed login attempt from unknown IP',
        ipAddress: '192.168.1.200',
      }
    ]
  });

  console.log('✅ Database seeded successfully!');
  console.log('📧 Admin credentials:');
  console.log('   Email: admin@miichisoft.com');
  console.log('   Password: Admin@123456');
  console.log('📧 Test user credentials:');
  console.log('   Email: john.doe@miichisoft.com');
  console.log('   Password: Test@123456');
}

main()
  .catch((e) => {
    console.error('❌ Error seeding database:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
