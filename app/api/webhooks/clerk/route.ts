import { Webhook } from "svix";
import { headers } from "next/headers";
import { WebhookEvent } from "@clerk/nextjs/server";
import prisma from "@/lib/prisma";

export async function POST(req: Request) {
    const WEBHOOK_SECRET = process.env.CLERK_WEBHOOK_SECRET;

    if (!WEBHOOK_SECRET) {
        throw new Error("Missing WEBHOOK_SECRET in environment variables.");
    }

    const headerPayload = await headers();
    const svix_id = headerPayload.get("svix-id");
    const svix_timestamp = headerPayload.get("svix-timestamp");
    const svix_signature = headerPayload.get("svix-signature");

    if (!svix_id || !svix_timestamp || !svix_signature) {
        return new Response("Missing Svix headers", {status: 400});
    }

    const payload = await req.json();
    const body = JSON.stringify(payload);

    const wh = new Webhook(WEBHOOK_SECRET);
    let evt: WebhookEvent;
    try {
        evt = wh.verify(body, {
            "svix-id": svix_id,
            "svix-timestamp": svix_timestamp,
            "svix-signature": svix_signature,
        }) as WebhookEvent;
    } catch (err) {
        console.error("Webhook verification failed:", err);
        return new Response("Invalid webhook signature", {status: 400});
    }

    const eventType = evt.type;
    const clerkId = evt.data.id;

    console.log(`Webhook received: ${eventType} for Clerk ID: ${clerkId}`);

    if (eventType === "user.created") {
        try {
            const { username } = evt.data;

            if (!username) {
                return new Response("Missing username", { status: 400 });
            }

            const newUser = await prisma.user.create({
                data: {
                    clerkId: evt.data.id!,
                    username: evt.data.username!,
                    displayName: evt.data.username!,
                    avatarUrl: evt.data.image_url ?? null,
                },
            });
            console.log("User created in DB:", newUser);
        } catch (error) {
            console.error("Error creating user:", error);
            return new Response("Error creating user", { status: 500 });
        }
    }

    if (eventType === "user.updated") {
        try {
            const { username } = evt.data;

            if (!username) {
                return new Response("Missing username", { status: 400 });
            }

            const existingUser = await prisma.user.findUnique({
                where: { clerkId },
            });

            if (!existingUser) {
                return new Response("User not found", { status: 404 });
            }

            const updatedUser = await prisma.user.update({
                where: { clerkId },
                data: {
                    username: evt.data.username!,
                    avatarUrl: evt.data.image_url ?? null,
                },
            });

            console.log("User updated:", updatedUser);
        } catch (error) {
            console.error("Error updating user:", error);
            return new Response("Error updating user", { status: 500 });
        }
    }

    if (eventType === "user.deleted") {
        try {
            const userToDelete = await prisma.user.findUnique({
                where: { clerkId  },
            });

            if (!userToDelete) {
                console.warn("User not found, skipping delete.");
                return new Response("User not found", { status: 200 });
            }

            await prisma.user.delete({
                where: { clerkId },
            });

            console.log("User deleted from DB:", clerkId);
        } catch (error) {
            console.error("Error deleting user:", error);
            return new Response("Error deleting user", { status: 500 });
        }
    }

    return new Response("Webhook processed successfully", { status: 200 });
}
