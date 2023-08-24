import { test, expect } from "vitest";
import { subscribers, models } from "@teamkeel/testing";

test("subscriber - mutating field", async () => {
  const mary = await models.member.create({
    name: "Mary",
    email: "mary@keel.so",
  });

  const event = {
    eventName: "member.created",
    occurredAt: new Date(),
    target: {
      id: mary.id,
      type: "Member",
      data: mary,
    },
  };

  await subscribers.verifyEmail(event);

  const updatedMary = await models.member.findOne({ id: mary.id });

  expect(mary?.verified).toBeFalsy();
  expect(updatedMary?.verified).toBeTruthy();
});
