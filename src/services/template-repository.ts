import type { PromptTemplate } from "../types.js";
import { verifyContent } from "./prompt-builder.js";

export function serializeTemplateLayers(
  template: Pick<PromptTemplate, "layers">,
): string {
  return [
    template.layers.role,
    template.layers.objective,
    template.layers.constraints,
    template.layers.outputShape,
  ].join("\n");
}

export class TemplateRepository {
  constructor(
    private readonly kv: KVNamespace,
    private readonly hmacKey: string,
  ) {}

  async get(id: string, version?: number): Promise<PromptTemplate | null> {
    const key = version ? `template:${id}:v${version}` : `template:${id}`;
    return await this.kv.get<PromptTemplate>(key, "json");
  }

  async getVerified(id: string, version?: number): Promise<PromptTemplate | null> {
    const template = await this.get(id, version);
    if (!template) return null;

    const valid = await verifyContent(
      serializeTemplateLayers(template),
      template.hmacSignature,
      this.hmacKey,
    );

    if (!valid) {
      throw new Error(`Template integrity check failed: ${id}`);
    }

    return template;
  }

  async save(template: PromptTemplate): Promise<void> {
    const value = JSON.stringify(template);
    const metadata = {
      name: template.name,
      version: template.version,
      tags: template.tags,
      requiresHITL: template.requiresHITL,
      updatedAt: template.updatedAt,
    };

    await Promise.all([
      this.kv.put(`template:${template.id}`, value, { metadata }),
      this.kv.put(`template:${template.id}:v${template.version}`, value, {
        expirationTtl: 60 * 60 * 24 * 90,
      }),
    ]);
  }

  async listLatest(limit: number, cursor?: string): Promise<KVNamespaceListResult<unknown>> {
    return this.kv.list({
      prefix: "template:",
      limit,
      cursor,
    });
  }

  async deletePrimary(id: string): Promise<void> {
    await this.kv.delete(`template:${id}`);
  }
}
