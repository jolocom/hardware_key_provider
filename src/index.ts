import { IVaultedKeyProvider, IKeyDerivationArgs } from 'jolocom-lib/js/vaultedKeyProvider/types';
import { SoftwareKeyProvider } from 'jolocom-lib/js/vaultedKeyProvider/softwareProvider';
import { SecureElement } from 'secure-element-interface';
import { IDigestible } from 'jolocom-lib/js/linkedDataSignature/types';

export class HardwareKeyProvider implements IVaultedKeyProvider {
    private readonly pword: string
    private readonly seed: Buffer

    constructor() {
        const SecEl = new SecureElement();

        try {
            this.seed = SecEl.getPublicKey(0).slice(0, 32);
        } catch {
            SecEl.generateKeyPair(0);
        }

        try {
            this.pword = SecEl.getPublicKey(1).toString('base64').slice(0, 32);
        } catch {
            SecEl.generateKeyPair(1);
        }
    }

    public getPublicKey(derivationArgs: IKeyDerivationArgs): Buffer {
        return this.getSVKP().getPublicKey(this.fixDerivArgs(derivationArgs));
    }

    public getRandom(nr: number): Buffer {
        return SoftwareKeyProvider.getRandom(nr)
    }

    public sign(derivationArgs: IKeyDerivationArgs, digest: Buffer): Buffer {
        return this.getSVKP().sign(this.fixDerivArgs(derivationArgs), digest);
    }

    public static verify(digest: Buffer, publicKey: Buffer, signature: Buffer): boolean {
        return SoftwareKeyProvider.verify(digest, publicKey, signature);
    }

    public getPrivateKey(derivationArgs: IKeyDerivationArgs): Buffer {
        return this.getSVKP().getPrivateKey(this.fixDerivArgs(derivationArgs));
    }

    public async signDigestable(derivationArgs: IKeyDerivationArgs, toSign: IDigestible): Promise<Buffer> {
        return this.getSVKP().signDigestable(this.fixDerivArgs(derivationArgs), toSign);
    }

    public static async verifyDigestable(publicKey: Buffer, toVerify: IDigestible): Promise<boolean> {
        return SoftwareKeyProvider.verifyDigestable(publicKey, toVerify);
    }

    private getSVKP(): SoftwareKeyProvider {
        return SoftwareKeyProvider.fromSeed(this.seed, this.pword)
    }

    private fixDerivArgs(derivationArgs: IKeyDerivationArgs): IKeyDerivationArgs {
        return {
            derivationPath: derivationArgs.derivationPath,
            encryptionPass: this.pword
        };
    }
}
