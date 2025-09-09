import {UserResponse} from '@sharedTypes/MessageTypes';
import {User} from '@sharedTypes/DBTypes';
import {NextFunction, Request, Response} from 'express';
import CustomError from '../../classes/CustomError';
import fetchData from '../../utils/fetchData';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  VerifyRegistrationResponseOpts,
} from '@simplewebauthn/server';
import {Challenge, PasskeyUserPost} from '../../types/PasskeyTypes';
import challengeModel from '../models/challengeModel';
import passkeyUserModel from '../models/passkeyUserModel';
import {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/types';
import authenticatorDeviceModel from '../models/authenticatorDeviceModel';
import {Types} from 'mongoose';

// check environment variables
if (
  !process.env.NODE_ENV ||
  !process.env.RP_ID ||
  !process.env.AUTH_URL ||
  !process.env.JWT_SECRET ||
  !process.env.RP_NAME
) {
  throw new Error('Environment variables not set');
}

const {NODE_ENV, RP_ID, AUTH_URL, JWT_SECRET, RP_NAME} = process.env;

console.log(NODE_ENV, JWT_SECRET);

// Registration handler
const setupPasskey = async (
  req: Request<{}, {}, User>,
  res: Response<{
    email: string;
    options: PublicKeyCredentialCreationOptionsJSON;
  }>,
  next: NextFunction,
) => {
  try {
    const options: RequestInit = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(req.body),
    };
    const userResponse = await fetchData<UserResponse>(
      AUTH_URL + '/api/v1/users',
      options,
    );

    if (!userResponse) {
      next(new CustomError('User not created', 400));
      return;
    }

    const regOptions = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName: userResponse.user.username,
      attestationType: 'none',
      timeout: 60000,
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
      supportedAlgorithmIDs: [-7, -257],
    });

    // console.log(regOptions);

    const challenge: Challenge = {
      challenge: regOptions.challenge,
      email: userResponse.user.email,
    };

    await challengeModel.create(challenge);

    const passkeyUser: PasskeyUserPost = {
      email: userResponse.user.email,
      userId: userResponse.user.user_id,
      devices: [],
    };

    await passkeyUserModel.create(passkeyUser);

    res.json({
      email: userResponse.user.email,
      options: regOptions,
    });
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Registration verification handler
const verifyPasskey = async (
  req: Request<
    {},
    {},
    {
      email: string;
      registrationOptions: RegistrationResponseJSON;
    }
  >,
  res: Response<UserResponse>,
  next: NextFunction,
) => {
  try {
    const expectedChallenge = await challengeModel.findOne({
      email: req.body.email,
    });

    if (!expectedChallenge) {
      next(new CustomError('challenge not found', 404));
      return;
    }

    const opts: VerifyRegistrationResponseOpts = {
      response: req.body.registrationOptions,
      expectedChallenge: expectedChallenge.challenge,
      expectedOrigin:
        NODE_ENV === 'development'
          ? `http://${RP_ID}:5173`
          : `https://${RP_ID}`,
      expectedRPID: RP_ID,
    };
    const verification = await verifyRegistrationResponse(opts);

    const {verified, registrationInfo} = verification;

    if (!verified || !registrationInfo) {
      next(new CustomError('Verification failed', 403));
      return;
    }

    const {credentialPublicKey, credentialID, counter} = registrationInfo;
    const existingDevice = await authenticatorDeviceModel.findOne({
      credentialID,
    });

    if (existingDevice) {
      next(new CustomError('Device already registered', 400));
      return;
    }

    const newDevice = new authenticatorDeviceModel({
      email: req.body.email,
      credentialPublicKey: Buffer.from(credentialPublicKey),
      credentialID,
      counter,
      transports: req.body.registrationOptions.response.transports,
    });

    const newDeviceResult = await newDevice.save();

    const user = await passkeyUserModel.findOne({email: req.body.email});
    if (!user) {
      next(new CustomError('User not found', 404));
      return;
    }
    // dokumentin taulukon päivittäminen
    user.devices.push(newDeviceResult._id as Types.ObjectId);
    await user.save();

    await challengeModel.findOneAndDelete({email: req.body.email});
    const userResponse = await fetchData<UserResponse>(
      AUTH_URL + '/api/v1/users/' + user.userId,
    );
    res.json(userResponse);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Generate authentication options handler
const authenticationOptions = async (
  req: Request<{}, {}, {email: string}>,
  res: Response<>,
  next: NextFunction,
) => {
  try {
    // TODO: Retrieve user and associated devices from DB
    // TODO: Generate authentication options
    // TODO: Save challenge to DB
    // TODO: Send options in response
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Authentication verification and login handler
const verifyAuthentication = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    // TODO: Retrieve expected challenge from DB
    // TODO: Verify authentication response
    // TODO: Update authenticator's counter
    // TODO: Clear challenge from DB after successful authentication
    // TODO: Generate and send JWT token
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {
  setupPasskey,
  verifyPasskey,
  authenticationOptions,
  verifyAuthentication,
};
