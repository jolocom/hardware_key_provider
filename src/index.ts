import {IVaultedKeyProvider, IKeyDerivationArgs, KeyTypes} from 'jolocom-lib/js/vaultedKeyProvider/types';
import {SoftwareKeyProvider} from 'jolocom-lib/js/vaultedKeyProvider/softwareProvider';
import {SecureElement, ISecureElement} from 'secure-element-interface';
import { IDigestable } from 'jolocom-lib/js/linkedDataSignature/types';

export class HardwareKeyProvider implements IVaultedKeyProvider {
  private readonly SecEl: ISecureElement;

  constructor() {
    this.SecEl = new SecureElement();

    try {
      this.SecEl.getPublicKey(0);
    } catch {
      this.SecEl.generateKeyPair(0);
    }
  }

  public getPublicKey(derivationArgs: IKeyDerivationArgs): Buffer {
    return this.getSVKP().getPublicKey(derivationArgs);
  }

  public getRandom(nr: number): Buffer {
    return this.SecEl.getRandom(nr);
  }

  public sign(derivationArgs: IKeyDerivationArgs, digest: Buffer): Buffer {
    return this.getSVKP().sign(derivationArgs, digest);
  }

  public static verify(digest: Buffer, publicKey: Buffer, signature: Buffer): boolean {
    return SoftwareKeyProvider.verify(digest, publicKey, signature);
  }

  public getPrivateKey(derivationArgs: IKeyDerivationArgs): Buffer {
    return this.getSVKP().getPrivateKey(derivationArgs);
  }

  public async signDigestable (derivationArgs: IKeyDerivationArgs, toSign: IDigestable): Promise<Buffer> {
    return this.getSVKP().signDigestable(derivationArgs, toSign);
  }

  public static async verifyDigestable(publicKey: Buffer, toVerify: IDigestable): Promise<boolean> {
    return SoftwareKeyProvider.verifyDigestable(publicKey, toVerify);
  }

  private getSVKP(): SoftwareKeyProvider {
    const buf: Buffer = this.SecEl.getPublicKey(0);
    return new SoftwareKeyProvider(buf.slice(buf.length - 128), 'password');
  }
}
