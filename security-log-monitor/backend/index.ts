import express, { type Request, type Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';

dotenv.config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const createLogSchema = z.object({
  eventType: z.enum([
    'AUTH_SUCCESS',
    'AUTH_FAILURE',
    'BRUTE_FORCE_ATTEMPT',
    'SUSPICIOUS_IP',
    'INJECTION_ATTEMPT',
  ]),
  severity: z.enum(['INFO', 'WARNING', 'CRITICAL']).default('INFO'),
  ipAddress: z.string().ipv4({ message: 'Endereço IPv4 inválido' }),
  userAgent: z.string().optional(),
  username: z.string().optional(),
  details: z.string().optional(),
});

app.get('/api/health', (req: Request, res: Response) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.post('/api/logs', async (req: Request, res: Response) => {
  try {
    const validatedData = createLogSchema.parse(req.body);

    const log = await prisma.securityLog.create({
      data: validatedData,
    });

    if (
      log.severity === 'CRITICAL' ||
      log.eventType === 'BRUTE_FORCE_ATTEMPT' ||
      log.eventType === 'INJECTION_ATTEMPT'
    ) {
      await prisma.incidentAlert.create({
        data: {
          title: `Alerta de Segurança: ${log.eventType}`,
          description: `Atividade suspeita detetada a partir do IP \({log.ipAddress}. Detalhes:\){log.details || 'Nenhum'}`,
          severity: log.severity === 'CRITICAL' ? 'CRITICAL' : 'WARNING',
          ipAddress: log.ipAddress,
          logId: log.id,
        },
      });
    }

    return res.status(201).json(log);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Erro de validação', details: error.issues });
    }
    console.error('Erro ao guardar log:', error);
    return res.status(500).json({ error: 'Erro interno do servidor ao registar log' });
  }
});

app.get('/api/logs', async (req: Request, res: Response) => {
  try {
    const { severity, eventType, ipAddress } = req.query;

    const where: any = {};
    if (severity) where.severity = String(severity);
    if (eventType) where.eventType = String(eventType);
    if (ipAddress) where.ipAddress = String(ipAddress);

    const logs = await prisma.securityLog.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: 100,
    });

    return res.json(logs);
  } catch (error) {
    console.error('Erro ao procurar logs:', error);
    return res.status(500).json({ error: 'Erro ao procurar logs de segurança' });
  }
});

app.get('/api/alerts', async (req: Request, res: Response) => {
  try {
    const alerts = await prisma.incidentAlert.findMany({
      include: { log: true },
      orderBy: { createdAt: 'desc' },
    });

    return res.json(alerts);
  } catch (error) {
    console.error('Erro ao procurar alertas:', error);
    return res.status(500).json({ error: 'Erro ao procurar alertas' });
  }
});

app.listen(PORT, () => {
  console.log(`🛡️  Security Log Monitor API ativa na porta ${PORT}`);
});