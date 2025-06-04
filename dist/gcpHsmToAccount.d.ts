import { KeyManagementServiceClient } from '@google-cloud/kms';
import { LocalAccount } from 'viem/accounts';
export type GcpHsmAccount = LocalAccount<'gcpHsm'>;
export declare function gcpHsmToAccount({ hsmKeyVersion, kmsClient: kmsClient_, }: {
    hsmKeyVersion: string;
    kmsClient?: KeyManagementServiceClient;
}): Promise<GcpHsmAccount>;
