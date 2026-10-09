import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { CreateUserDto } from '../dto/create-user.dto';
import { Role, RoleDocument } from '../schemas/role.schema';
import { User, UserDocument } from '../schemas/user.schema';
import { PrivescAgent } from './privesc.agent';
import { PrivescEngine, PrivescReport } from './privesc.engine';
import { IncidentAssessment, SecurityJudge } from './security.judge';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
    @InjectModel(Role.name) private readonly roleModel: Model<RoleDocument>,
  ) {}

  async create(createUserDto: CreateUserDto) {
    const existingUser = await this.userModel.findOne({
      userName: createUserDto.userName,
    });

    if (existingUser) {
      return {
        message: 'user already exists',
      };
    }

    const foundRoles = await this.roleModel
      .find({ roleId: { $in: createUserDto.role } })
      .lean();

    const foundRoleIds = foundRoles.map((role) => role._id);

    if (foundRoleIds.length !== createUserDto.role.length) {
      const missingRoleIds = createUserDto.role.filter(
        (roleId) => !foundRoles.some((role) => role.roleId === roleId),
      );

      return {
        message: `Role not found: ${missingRoleIds.join(', ')}`,
      };
    }

    const createdUser = await this.userModel.create({
      userName: createUserDto.userName,
      roleId: foundRoleIds,
    });

    const shouldScan = createUserDto.shouldIncludeScan;
    const selectedPassKey = foundRoles[0]?.passKey;
    const selectedRoleId = foundRoles[0]?.roleId;

    // When the scan box is ticked, run the Claude-driven privilege-escalation
    // agent against <role>@<host>. Claude is the brain: it does its own recon
    // and decides each command. If the agent fails (e.g. Bedrock unreachable),
    // fall back to the deterministic rule engine so the demo still works.
    let privescReport: PrivescReport | undefined;
    if (shouldScan && selectedPassKey && selectedRoleId) {
      const rawSshHost = process.env.POST_AGENT_SSH_HOST ?? process.env.SSH_HOST;
      if (rawSshHost) {
        const host = `${selectedRoleId.toLowerCase()}${rawSshHost}`;
        try {
          privescReport = await new PrivescAgent({
            host,
            password: selectedPassKey,
          }).run();
        } catch (error) {
          const detail =
            error instanceof Error ? error.message : 'unknown error';
          console.error(
            '[privesc] Claude agent failed, falling back to deterministic engine:',
            detail,
          );
          try {
            privescReport = await new PrivescEngine({
              host,
              password: selectedPassKey,
            }).run();
          } catch (fallbackError) {
            const fbDetail =
              fallbackError instanceof Error
                ? fallbackError.message
                : 'unknown error';
            console.error('[privesc] fallback engine failed:', fbDetail);
          }
        }
      } else {
        console.warn('[privesc] POST_AGENT_SSH_HOST not set; skipping scan.');
      }
    }

    // A separate judge agent reviews the escalation report and decides whether
    // an impactful security incident occurred (drives the UI tick/cross).
    let incident: IncidentAssessment | undefined;
    if (privescReport) {
      incident = await new SecurityJudge().assess(privescReport);
      console.log(
        `[security-judge] verdict=${incident.verdict} severity=${incident.severity} - ${incident.title}`,
      );
    }

    const message = privescReport
      ? privescReport.summary
      : `User '${createUserDto.userName}' created successfully.`;

    return {
      message,
      createdUser,
      roles: foundRoles,
      shouldIncludeScan: createUserDto.shouldIncludeScan,
      privesc: privescReport,
      incident,
    };
  }
}
